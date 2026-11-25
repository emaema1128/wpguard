<?php

declare(strict_types=1);

namespace WPGuard;

use WPGuard\Notifier\StdoutNotifier;

final class Cli
{
    private const HELP = <<<'TXT'
        WPGuard - WordPress セキュリティ監視エージェント

        使い方: wpguard <コマンド> [オプション]

        コマンド:
          sites                          検出したサイトの一覧
          scan [--full] [--site=NAME]    スキャンする (--full: 全ファイルのハッシュを再計算)
          baseline (--site=NAME|--all)   ベースラインを作り直す (現在の状態を正常として記録)
          findings [--site=NAME]         未対応の検知の一覧
          ack <ID>... | --site=NAME --all | --all
                                         検知を「確認済み」にする
          test-slack                     Slack にテスト通知を送る
          help                           このヘルプ

        共通オプション:
          --config=PATH   設定ファイル (既定: 環境変数 WPGUARD_CONFIG か、インストール先の config.php)
          --dry-run       Slack に送らず、通知内容を画面に表示する
          -v, --verbose   ログを画面にも表示する

        TXT;

    /** @param string[] $argv */
    public function run(array $argv): int
    {
        [$command, $args, $opts] = self::parse(array_slice($argv, 1));
        if ($command === null || $command === 'help' || isset($opts['help']) || isset($opts['h'])) {
            fwrite(STDOUT, self::HELP);
            return 0;
        }

        try {
            $config = Config::load(isset($opts['config']) ? (string) $opts['config'] : null);
            $app = new App(
                $config,
                isset($opts['dry-run']) ? new StdoutNotifier() : null,
                null,
                isset($opts['v']) || isset($opts['verbose']),
            );

            return match ($command) {
                'sites' => $this->sites($app),
                'scan' => $this->scan($app, $opts),
                'baseline' => $this->baseline($app, $opts),
                'findings' => $this->findings($app, $opts),
                'ack' => $this->ack($app, $args, $opts),
                'test-slack' => $this->testSlack($app),
                default => $this->unknown($command),
            };
        } catch (\Throwable $e) {
            fwrite(STDERR, "エラー: {$e->getMessage()}\n");
            return 1;
        }
    }

    private function sites(App $app): int
    {
        $sites = $app->discover();
        $rows = $app->db->sites();
        if ($sites === []) {
            fwrite(STDOUT, "WordPress サイトが見つかりませんでした。設定の roots を確認してください。\n");
            return 0;
        }
        $open = [];
        foreach ($app->db->openFindings() as $f) {
            $open[$f['site_id']] = ($open[$f['site_id']] ?? 0) + 1;
        }
        $table = [['サイト', 'WP', '最終スキャン', '未対応', 'パス']];
        foreach ($sites as $name => $site) {
            $row = $rows[$site->path] ?? null;
            $table[] = [
                $name,
                $site->wpVersion ?? '?',
                $row && $row['last_scan'] ? date('Y-m-d H:i', (int) $row['last_scan']) : '未スキャン',
                $row ? (string) ($open[$row['id']] ?? 0) : '-',
                $site->path,
            ];
        }
        self::printTable($table);
        fwrite(STDOUT, sprintf("\n%d サイト\n", count($sites)));
        return 0;
    }

    private function scan(App $app, array $opts): int
    {
        if (!$app->lock()) {
            fwrite(STDERR, "別の wpguard が実行中のため終了します\n");
            return 3;
        }
        $results = $app->scan(isset($opts['full']), self::siteOpt($opts));
        $this->printResults($results);
        return 0;
    }

    private function baseline(App $app, array $opts): int
    {
        $site = self::siteOpt($opts);
        if ($site === null && !isset($opts['all'])) {
            fwrite(STDERR, "--site=NAME か --all を指定してください\n");
            return 1;
        }
        if (!$app->lock()) {
            fwrite(STDERR, "別の wpguard が実行中のため終了します\n");
            return 3;
        }
        $this->printResults($app->rebaseline($site));
        return 0;
    }

    private function findings(App $app, array $opts): int
    {
        $siteId = $this->siteId($app, self::siteOpt($opts));
        $rows = $app->db->openFindings($siteId);
        if ($rows === []) {
            fwrite(STDOUT, "未対応の検知はありません\n");
            return 0;
        }
        $table = [['ID', '重要度', 'サイト', '内容', 'ファイル', '検知日時']];
        foreach ($rows as $r) {
            $sev = Severity::from($r['severity']);
            $table[] = [
                (string) $r['id'], $sev->emoji() . ' ' . $sev->label(), $r['site_name'], $r['message'], $r['path'],
                date('Y-m-d H:i', (int) $r['detected_at']),
            ];
        }
        self::printTable($table);
        fwrite(STDOUT, sprintf("\n%d 件\n", count($rows)));
        return 0;
    }

    private function ack(App $app, array $args, array $opts): int
    {
        $now = time();
        if (isset($opts['all'])) {
            $n = $app->db->ackAllFindings($this->siteId($app, self::siteOpt($opts)), $now);
        } else {
            $ids = array_map('intval', array_filter($args, 'ctype_digit'));
            if ($ids === [] || count($ids) !== count($args)) {
                fwrite(STDERR, "検知の ID を指定してください (例: wpguard ack 12 13)\n");
                return 1;
            }
            $n = $app->db->ackFindings($ids, $now);
        }
        fwrite(STDOUT, "{$n} 件を確認済みにしました\n");
        return 0;
    }

    private function testSlack(App $app): int
    {
        $ok = $app->notifications->notifyEvent(
            Severity::Info,
            'WPGuard',
            'テスト通知です',
            'この通知が届いていれば、Slack との連携は正常です。',
        );
        fwrite($ok ? STDOUT : STDERR, $ok ? "送信しました\n" : "送信に失敗しました。ログを確認してください\n");
        return $ok ? 0 : 1;
    }

    private function unknown(string $command): int
    {
        fwrite(STDERR, "不明なコマンドです: {$command}\nwpguard help で使い方を表示します\n");
        return 1;
    }

    private function siteId(App $app, ?string $name): ?int
    {
        if ($name === null) {
            return null;
        }
        foreach ($app->db->sites() as $row) {
            if ($row['name'] === $name) {
                return (int) $row['id'];
            }
        }
        throw new \RuntimeException("サイトが見つかりません: {$name}");
    }

    /** @param array<string,ScanResult> $results */
    private function printResults(array $results): void
    {
        $table = [['サイト', '種類', 'ファイル数', '緊急', '警告', '情報', '秒']];
        foreach ($results as $name => $r) {
            $c = $r->counts();
            $table[] = [
                $name, $r->baseline ? 'ベースライン作成' : 'スキャン', (string) $r->files,
                (string) $c['critical'], (string) $c['warning'], (string) $c['info'], sprintf('%.1f', $r->seconds),
            ];
        }
        self::printTable($table);
    }

    private static function siteOpt(array $opts): ?string
    {
        return isset($opts['site']) && $opts['site'] !== true ? (string) $opts['site'] : null;
    }

    /** @return array{?string, string[], array<string,string|true>} */
    private static function parse(array $argv): array
    {
        $command = null;
        $args = [];
        $opts = [];
        foreach ($argv as $a) {
            if (str_starts_with($a, '--')) {
                $parts = explode('=', substr($a, 2), 2);
                $opts[$parts[0]] = $parts[1] ?? true;
            } elseif (str_starts_with($a, '-') && strlen($a) > 1) {
                foreach (str_split(substr($a, 1)) as $flag) {
                    $opts[$flag] = true;
                }
            } elseif ($command === null) {
                $command = $a;
            } else {
                $args[] = $a;
            }
        }
        return [$command, $args, $opts];
    }

    /** @param string[][] $rows */
    private static function printTable(array $rows): void
    {
        $widths = [];
        foreach ($rows as $row) {
            foreach ($row as $i => $cell) {
                $widths[$i] = max($widths[$i] ?? 0, mb_strwidth($cell));
            }
        }
        foreach ($rows as $n => $row) {
            $line = [];
            foreach ($row as $i => $cell) {
                $line[] = $cell . str_repeat(' ', $widths[$i] - mb_strwidth($cell));
            }
            fwrite(STDOUT, rtrim(implode('  ', $line)) . "\n");
            if ($n === 0) {
                fwrite(STDOUT, str_repeat('-', array_sum($widths) + 2 * (count($widths) - 1)) . "\n");
            }
        }
    }
}
