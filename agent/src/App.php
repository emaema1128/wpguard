<?php

declare(strict_types=1);

namespace WPGuard;

use WPGuard\Checksums\ChecksumProvider;
use WPGuard\Checksums\NullChecksums;
use WPGuard\Checksums\WordPressOrgChecksums;
use WPGuard\Notifier\Notifier;
use WPGuard\Notifier\SlackNotifier;
use WPGuard\Notifier\StdoutNotifier;

final class App
{
    public readonly Database $db;
    public readonly Logger $logger;
    public readonly NotificationService $notifications;
    private Scanner $scanner;
    private ?Quarantine $quarantine = null;
    private ?DbScanner $dbScanner = null;
    /** @var resource|null */
    private $lock = null;

    public function __construct(
        public readonly Config $config,
        ?Notifier $notifier = null,
        ?Logger $logger = null,
        bool $verbose = false,
        ?ChecksumProvider $checksums = null,
    ) {
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
        $checksums ??= $config->get('checksums')
            ? new WordPressOrgChecksums($this->db, $this->logger, (int) $config->get('checksum_timeout'))
            : new NullChecksums();
        $rulesFile = (string) ($config->get('rules_file') ?? dirname(__DIR__) . '/rules/patterns.php');

        $this->scanner = new Scanner(
            $this->db,
            new Hasher((int) $config->get('max_hash_bytes')),
            new Classifier(),
            PatternScanner::fromFile($rulesFile, (int) $config->get('max_scan_bytes')),
            new OfficialVerifier($checksums, (string) $this->config->get('sentinel_manifest')),
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

            if ($full || $baselineOnly) {
                $this->scanDatabase($site, $now);
            }

            if ($baselineOnly) {
                $isNew = $row['last_scan'] === null;
                $body = sprintf("📁 `%s`\n📄 %d ファイルをベースラインとして記録しました", $site->path, $result->files);
                $suspicious = count($result->findings);
                if ($suspicious > 0) {
                    $body .= "\n⚠️ この時点で {$suspicious} 件の怪しいファイルが見つかりました。続けて通知します。";
                }
                $this->notifications->notifyEvent(
                    $suspicious > 0 ? Severity::Warning : Severity::Info,
                    $name,
                    $isNew ? '監視を開始しました' : 'ベースラインを作り直しました',
                    $body,
                );
            }
            $this->notifications->notifyPending($site, $now);
            $results[$name] = $result;
        }

        $this->db->pruneNotifications($now - 30 * 86400);
        if ($full && $only === null) {
            $purged = $this->quarantine()->purge($now - (int) $this->config->get('quarantine_days') * 86400, $now);
            if ($purged > 0) {
                $this->logger->info("保管期間を過ぎた隔離ファイルを {$purged} 件削除しました");
            }
        }
        return $results;
    }

    /**
     * Inspects one site's database. Failures (e.g. unreadable wp-config.php) are reported
     * once, and again only when the error changes, so a broken site does not alert every day.
     */
    private function scanDatabase(Site $site, int $now): ?ScanResult
    {
        if (!$this->config->get('db_scan')) {
            return null;
        }
        if (!extension_loaded('pdo_mysql')) {
            $this->logger->warning('PHP の pdo_mysql 拡張モジュールがないため、DB の検査を行いません (apt-get install php-mysql)');
            return null;
        }
        $this->dbScanner ??= new DbScanner($this->db, (array) $this->config->get('db_script_allow'), (int) $this->config->get('db_timeout'));
        try {
            $r = $this->dbScanner->scan($site, $now);
            $this->db->setSiteState((int) $site->id, 'db_error', null);
            $c = $r->counts();
            $this->logger->info(sprintf('%s: DB 検査 %d 件 緊急 %d / 警告 %d / 情報 %d, %.1f 秒', $site->name, $r->files, $c['critical'], $c['warning'], $c['info'], $r->seconds));
            return $r;
        } catch (\Throwable $e) {
            $msg = $e instanceof \PDOException ? 'DB に接続できません: ' . $e->getMessage() : $e->getMessage();
            $this->logger->warning("{$site->name}: DB を検査できません: {$msg}");
            if ($this->db->siteState((int) $site->id, 'db_error') !== $msg) {
                $this->db->setSiteState((int) $site->id, 'db_error', $msg);
                $this->notifications->notifyEvent(Severity::Warning, $site->name, 'DB を検査できませんでした', '`' . str_replace('`', "'", $msg) . '`');
            }
            return null;
        }
    }

    /** @return array<string,ScanResult> */
    public function dbScan(?string $only = null, ?int $now = null): array
    {
        $now ??= time();
        $sites = $this->syncSites($now);
        if ($only !== null && !isset($sites[$only])) {
            throw new \RuntimeException("サイトが見つかりません: {$only}");
        }
        $out = [];
        foreach ($sites as $name => $site) {
            if ($only !== null && $name !== $only) {
                continue;
            }
            $r = $this->scanDatabase($site, $now);
            if ($r !== null) {
                $out[$name] = $r;
                $this->notifications->notifyPending($site, $now);
            }
        }
        return $out;
    }

    /**
     * Turns off two-factor authentication for one user of one site (lost phone and recovery codes).
     * The user must set it up again at the next login. This is the only place the agent writes to a site's database.
     */
    public function resetTwoFactor(string $siteName, string $login, ?\PDO $pdo = null): void
    {
        $site = $this->siteRow($siteName);
        $c = WpConfigReader::read((string) $site['path']);
        if ($c === null || !preg_match('/^[A-Za-z0-9_]+$/', $c['prefix'])) {
            throw new \RuntimeException('wp-config.php から DB の接続情報を読み取れません');
        }
        $pdo ??= new \PDO(WpConfigReader::dsn($c), $c['user'], $c['password'], [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 5]);
        $p = $c['prefix'];
        $st = $pdo->prepare("SELECT ID FROM {$p}users WHERE user_login = ?");
        $st->execute([$login]);
        $id = $st->fetchColumn();
        if ($id === false) {
            throw new \RuntimeException("ユーザーが見つかりません: {$login}");
        }
        $pdo->beginTransaction();
        $pdo->prepare("DELETE FROM {$p}usermeta WHERE user_id = ? AND meta_key IN ('wpguard_2fa_secret', 'wpguard_2fa_pending', 'wpguard_2fa_last_step', 'wpguard_2fa_recovery', 'wpguard_2fa_grace_start')")->execute([$id]);
        // Grace period already over: the user sets it up again on the login screen.
        $pdo->prepare("INSERT INTO {$p}usermeta (user_id, meta_key, meta_value) VALUES (?, 'wpguard_2fa_grace_start', '1')")->execute([$id]);
        $pdo->commit();

        $this->logger->info("二要素認証を解除しました: {$siteName} {$login}");
        $this->notifications->notifyEvent(Severity::Warning, $siteName, '二要素認証を解除しました (サーバーでの操作)', sprintf(
            "👤 ユーザー: `%s`\n次回のログイン時に、ログイン画面で設定し直してもらいます。本人からの依頼でなければ、すぐに確認してください。",
            str_replace('`', "'", $login),
        ));
    }

    /** Sends the daily digest. Returns false when Slack could not be reached. */
    public function digest(?int $now = null): bool
    {
        $now ??= time();
        $this->syncSites($now);
        $waf = new WafLog((array) $this->config->get('waf_logs'), WafLog::systemTimezone());
        return $this->notifications->sendRaw((new Digest($this->db, $this->config, $waf))->build($now));
    }

    public function quarantine(): Quarantine
    {
        return $this->quarantine ??= new Quarantine($this->db, (string) $this->config->get('data_dir') . '/quarantine');
    }

    /** @return array{id:int,path:string,sha256:?string,site:string} */
    public function isolateFinding(int $findingId, bool $force, ?int $now = null): array
    {
        $f = $this->db->finding($findingId);
        if ($f === null) {
            throw new \RuntimeException("検知 #{$findingId} が見つかりません (wpguard findings で確認できます)");
        }
        if ($f['status'] === 'quarantined') {
            foreach ($this->db->quarantineEntries() as $q) {
                if ((int) $q['site_id'] === (int) $f['site_id'] && $q['path'] === $f['path'] && $q['restored_at'] === null) {
                    throw new \RuntimeException("検知 #{$findingId} のファイルは、すでに隔離しています (隔離 ID #{$q['id']})");
                }
            }
        }
        if ($f['kind'] === Finding::DELETED) {
            throw new \RuntimeException("検知 #{$findingId} はファイルが削除されたという検知なので、隔離するものはありません");
        }
        return $this->isolate($this->db->sites()[$f['site_path']], (string) $f['path'], $findingId, $force, $now ?? time());
    }

    /** @return array{id:int,path:string,sha256:?string,site:string} */
    public function isolatePath(string $siteName, string $path, bool $force, ?int $now = null): array
    {
        return $this->isolate($this->siteRow($siteName), $path, null, $force, $now ?? time());
    }

    /** @return array<string,mixed> */
    public function restore(int $id, ?int $now = null): array
    {
        $q = $this->quarantine()->restore($id, $now ?? time());
        $this->logger->info("隔離を解除しました: #{$id} {$q['site_name']} {$q['path']}");
        $this->notifications->notifyEvent(Severity::Warning, (string) $q['site_name'], '隔離したファイルを元に戻しました', sprintf('📄 `%s`  (隔離 ID #%d)', str_replace('`', "'", (string) $q['path']), $id));
        return $q;
    }

    /** @param array<string,mixed> $site */
    private function isolate(array $site, string $path, ?int $findingId, bool $force, int $now): array
    {
        $r = $this->quarantine()->isolate($site, $path, $findingId, $force, $now);
        $r['site'] = (string) $site['name'];
        $this->logger->info("隔離しました: #{$r['id']} {$site['name']} {$r['path']}");
        $this->notifications->notifyEvent(Severity::Info, (string) $site['name'], 'ファイルを隔離しました', sprintf(
            "📄 `%s`\n🗄 隔離 ID #%d — 元に戻すには `wpguard restore %d`",
            str_replace('`', "'", $r['path']), $r['id'], $r['id'],
        ));
        return $r;
    }

    /** @return array<string,mixed> */
    public function siteRow(string $name): array
    {
        foreach ($this->db->sites() as $row) {
            if ($row['name'] === $name) {
                return $row;
            }
        }
        throw new \RuntimeException("サイトが見つかりません: {$name} (wpguard sites で一覧を確認できます)");
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
