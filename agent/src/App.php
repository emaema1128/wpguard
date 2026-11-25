<?php

declare(strict_types=1);

namespace WPGuard;

use WPGuard\Notifier\Notifier;
use WPGuard\Notifier\SlackNotifier;
use WPGuard\Notifier\StdoutNotifier;

final class App
{
    public readonly Database $db;
    public readonly Logger $logger;
    public readonly NotificationService $notifications;
    private Scanner $scanner;
    /** @var resource|null */
    private $lock = null;

    public function __construct(public readonly Config $config, ?Notifier $notifier = null, ?Logger $logger = null, bool $verbose = false)
    {
        date_default_timezone_set((string) $config->get('timezone'));
        $this->logger = $logger ?? new Logger((string) $config->get('log_file'), $verbose);

        $dataDir = (string) $config->get('data_dir');
        if (!is_dir($dataDir) && !@mkdir($dataDir, 0700, true)) {
            throw new \RuntimeException("データディレクトリを作成できません: {$dataDir}");
        }
        if ((fileperms($dataDir) & 0077) !== 0) {
            $this->logger->warning("データディレクトリが他のユーザーからアクセス可能です。chmod 700 {$dataDir} を推奨します");
        }
        $dbFile = $dataDir . '/state.sqlite';
        $this->db = new Database($dbFile);
        @chmod($dbFile, 0600);

        $notifier ??= $this->makeNotifier();
        $this->notifications = new NotificationService($notifier, $this->db, $config, $this->logger);
        $this->scanner = new Scanner(
            $this->db,
            new Hasher((int) $config->get('max_hash_bytes')),
            new Classifier(),
            (array) $config->get('exclude'),
        );
    }

    private function makeNotifier(): Notifier
    {
        $default = (string) $this->config->slack('webhook_url');
        $bySeverity = (array) $this->config->slack('webhooks');
        if ($default === '' && $bySeverity === []) {
            $this->logger->warning('Slack の Webhook URL が未設定のため、通知は標準出力に表示します');
            return new StdoutNotifier();
        }
        return new SlackNotifier($default, $bySeverity, (int) $this->config->slack('timeout'), $this->logger);
    }

    /** Prevents overlapping runs (e.g. an hourly scan still going when the next cron fires). */
    public function lock(): bool
    {
        $file = (string) $this->config->get('data_dir') . '/wpguard.lock';
        $h = fopen($file, 'c');
        @chmod($file, 0600);
        if ($h === false || !flock($h, LOCK_EX | LOCK_NB)) {
            return false;
        }
        $this->lock = $h;
        return true;
    }

    /** @return array<string,Site> */
    public function discover(): array
    {
        $discovery = new SiteDiscovery(
            (array) $this->config->get('roots'),
            (int) $this->config->get('discovery_max_depth'),
            (array) $this->config->get('site_names'),
            $this->logger,
        );
        return $discovery->discover();
    }

    /** @return array<string,ScanResult> keyed by site name */
    public function scan(bool $full = false, ?string $only = null, ?int $now = null): array
    {
        $now ??= time();
        $sites = $this->syncSites($now);
        if ($only !== null && !isset($sites[$only])) {
            throw new \RuntimeException("サイトが見つかりません: {$only} (wpguard sites で一覧を確認できます)");
        }
        $rows = $this->db->sites();
        $allPaths = array_map(static fn (Site $s) => $s->path, $sites);

        $results = [];
        foreach ($sites as $name => $site) {
            if ($only !== null && $name !== $only) {
                continue;
            }
            $row = $rows[$site->path];
            $baselineOnly = (int) $row['baseline_done'] === 0;
            $skipDirs = array_values(array_filter($allPaths, static fn (string $p) => str_starts_with($p, $site->path . '/')));

            try {
                $result = $this->scanner->scan($site, $full, $baselineOnly, $skipDirs, $now);
            } catch (\Throwable $e) {
                $this->logger->error("スキャンに失敗しました: {$name}: " . $e->getMessage());
                $this->notifications->notifyEvent(Severity::Warning, $name, 'スキャンに失敗しました', '`' . str_replace('`', "'", $e->getMessage()) . '`');
                continue;
            }
            $this->db->updateSite((int) $site->id, ['last_scan' => $now, 'baseline_done' => 1]);

            foreach ($result->errors as $err) {
                $this->logger->warning("{$name}: {$err}");
            }
            $c = $result->counts();
            $this->logger->info(sprintf(
                '%s: %s %d ファイル (ハッシュ計算 %d) 緊急 %d / 警告 %d / 情報 %d, %.1f 秒',
                $name, $baselineOnly ? 'ベースライン作成' : ($full ? '全件スキャン' : '簡易スキャン'),
                $result->files, $result->hashed, $c['critical'], $c['warning'], $c['info'], $result->seconds,
            ));

            if ($baselineOnly) {
                $isNew = $row['last_scan'] === null;
                $this->notifications->notifyEvent(
                    Severity::Info,
                    $name,
                    $isNew ? '監視を開始しました' : 'ベースラインを作り直しました',
                    sprintf("📁 `%s`\n📄 %d ファイルをベースラインとして記録しました", $site->path, $result->files),
                );
            } else {
                $this->notifications->notifyPending($site, $now);
            }
            $results[$name] = $result;
        }

        $this->db->pruneNotifications($now - 30 * 86400);
        return $results;
    }

    /**
     * Throws away the stored state of a site (or all sites) and records the current files as the new baseline.
     *
     * @return array<string,ScanResult>
     */
    public function rebaseline(?string $only, ?int $now = null): array
    {
        $now ??= time();
        $sites = $this->syncSites($now);
        if ($only !== null && !isset($sites[$only])) {
            throw new \RuntimeException("サイトが見つかりません: {$only}");
        }
        foreach ($sites as $name => $site) {
            if ($only === null || $name === $only) {
                $this->db->clearFiles((int) $site->id);
                $this->db->updateSite((int) $site->id, ['baseline_done' => 0]);
            }
        }
        return $this->scan(false, $only, $now);
    }

    /** @return array<string,Site> discovered sites with ids, after recording new / missing sites */
    private function syncSites(int $now): array
    {
        $sites = $this->discover();
        $known = $this->db->sites();

        foreach ($sites as $name => $site) {
            $row = $known[$site->path] ?? null;
            unset($known[$site->path]);
            if ($row === null) {
                $site->id = $this->db->insertSite($site, $now);
                continue;
            }
            $site->id = (int) $row['id'];
            $update = [];
            if ($row['name'] !== $site->name) {
                $update['name'] = $site->name;
            }
            if ($row['wp_version'] !== $site->wpVersion) {
                $update['wp_version'] = $site->wpVersion;
            }
            if ($row['missing_since'] !== null) {
                $update['missing_since'] = null;
                $this->notifications->notifyEvent(Severity::Info, $name, 'サイトが再び見つかりました', "📁 `{$site->path}`");
            }
            if ($update !== []) {
                $this->db->updateSite($site->id, $update);
            }
        }

        foreach ($known as $path => $row) {
            if ($row['missing_since'] === null) {
                $this->db->updateSite((int) $row['id'], ['missing_since' => $now]);
                $this->notifications->notifyEvent(
                    Severity::Warning,
                    (string) $row['name'],
                    'サイトが見つからなくなりました',
                    "📁 `{$path}`\n削除や移動をした覚えがなければ確認してください。",
                );
            }
        }
        return $sites;
    }
}
