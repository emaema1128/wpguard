<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * A-09: looks inside each site's database (read-only) for what file monitoring cannot see:
 *   - scripts injected into posts and options (widgets, theme settings, ...)
 *   - the site URL being changed (to redirect visitors elsewhere)
 *   - administrators being added (even if the WordPress plugin was removed)
 *
 * On the first scan of a site, existing external scripts (analytics, ads) are only
 * recorded; from then on, a script from a new domain is reported.
 */
final class DbScanner
{
    private const MAX_ROWS = 20000;
    private const LIKE = ['%<script%', '%<iframe%', '%eval(%', '%fromCharCode%', '%unescape(%'];

    /** [rule, severity, description, regex] — the most serious first. */
    private const RULES = [
        ['js-eval-decode', 'critical', '難読化された JavaScript (eval と復号処理の組み合わせ)', '/\beval\s*\(\s*(?:window\.)?(?:atob|unescape|String\.fromCharCode|decodeURIComponent)\s*\(/i'],
        ['js-write-decode', 'critical', 'document.write と復号処理によるスクリプトの埋め込み', '/document\.write\s*\(\s*(?:unescape|atob|String\.fromCharCode|decodeURIComponent)\s*\(/i'],
        ['script-from-ip', 'critical', 'IP アドレスから読み込まれるスクリプト', '/<script[^>]+src\s*=\s*["\']?(?:https?:)?\/\/\d{1,3}(?:\.\d{1,3}){3}[:\/"\'\s>]/i'],
        ['js-charcode', 'warning', 'String.fromCharCode で隠された文字列', '/String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){20,}/i'],
        ['hidden-iframe', 'warning', '見えない iframe', '/<iframe\b[^>]*(?:\b(?:width|height)\s*=\s*["\']?[01]["\'\s>]|display\s*:\s*none|visibility\s*:\s*hidden)/i'],
    ];

    private const EXTERNAL_SCRIPT = '/<script\b[^>]*\bsrc\s*=\s*["\']?(?:https?:)?\/\/([^\/"\'\s>:]+)/i';

    /** @param string[] $allowDomains */
    public function __construct(private Database $db, private array $allowDomains, private int $timeout)
    {
    }

    public function scan(Site $site, int $now, ?\PDO $pdo = null): ScanResult
    {
        $start = microtime(true);
        $result = new ScanResult();
        $siteId = (int) $site->id;

        $config = WpConfigReader::read($site->path);
        if ($config === null) {
            throw new \RuntimeException('wp-config.php から DB の接続情報を読み取れません');
        }
        $p = $config['prefix'];
        if (!preg_match('/^[A-Za-z0-9_]+$/', $p)) {
            throw new \RuntimeException("テーブル接頭辞が不正です: {$p}");
        }
        $pdo ??= new \PDO(WpConfigReader::dsn($config), $config['user'], $config['password'], [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_TIMEOUT => $this->timeout,
        ]);

        $first = $this->db->siteState($siteId, 'db_scanned_at') === null;
        $options = $this->options($pdo, $p);
        $home = (string) ($options['home'] ?? $options['siteurl'] ?? '');
        $ownHost = strtolower((string) parse_url($home, PHP_URL_HOST));

        $this->checkUrls($site, $result, $options, $now);
        $this->checkAdmins($site, $result, $pdo, $p, $now, $first);

        $like = implode(' OR ', array_fill(0, count(self::LIKE), '%s LIKE ?'));
        $st = $pdo->prepare("SELECT option_name, option_value FROM {$p}options
            WHERE option_name NOT LIKE '\\_transient\\_%' AND option_name NOT LIKE '\\_site\\_transient\\_%'
            AND (" . sprintf($like, ...array_fill(0, count(self::LIKE), 'option_value')) . ') LIMIT ' . self::MAX_ROWS);
        $st->execute(self::LIKE);
        foreach ($st as $row) {
            $result->files++;
            $this->inspect($site, $result, 'db:options/' . $row['option_name'], "設定 ({$row['option_name']})", (string) $row['option_value'], $ownHost, $now, $first);
        }

        $st = $pdo->prepare("SELECT ID, post_type, post_title, post_content FROM {$p}posts
            WHERE post_type <> 'revision'
            AND (" . sprintf($like, ...array_fill(0, count(self::LIKE), 'post_content')) . ') LIMIT ' . self::MAX_ROWS);
        $st->execute(self::LIKE);
        foreach ($st as $row) {
            $result->files++;
            $title = mb_strimwidth((string) $row['post_title'], 0, 40, '…', 'UTF-8');
            $label = sprintf('%s #%d「%s」', $row['post_type'] === 'page' ? '固定ページ' : '投稿', $row['ID'], $title);
            $this->inspect($site, $result, 'db:posts/' . $row['ID'], $label, (string) $row['post_content'], $ownHost, $now, $first);
        }

        $this->db->setSiteState($siteId, 'db_scanned_at', (string) $now);
        $result->seconds = microtime(true) - $start;
        return $result;
    }

    /** @return array<string,string> */
    private function options(\PDO $pdo, string $p): array
    {
        $st = $pdo->query("SELECT option_name, option_value FROM {$p}options WHERE option_name IN ('siteurl', 'home')");
        $out = [];
        foreach ($st as $row) {
            $out[$row['option_name']] = (string) $row['option_value'];
        }
        return $out;
    }

    /** @param array<string,string> $options */
    private function checkUrls(Site $site, ScanResult $result, array $options, int $now): void
    {
        foreach (['siteurl', 'home'] as $name) {
            if (!isset($options[$name])) {
                continue;
            }
            $key = "url:{$name}";
            $old = $this->db->siteState((int) $site->id, $key);
            $new = $options[$name];
            if ($old !== null && $old !== $new) {
                $this->record($site, $result, new Finding(
                    Finding::MODIFIED, "db:options/{$name}", Severity::Critical, 'site-url',
                    "サイトの URL ({$name}) が変更されました (訪問者を別のサイトへ転送する手口の可能性)",
                    hash('sha256', $new), "{$old} → {$new}",
                ), $now);
            }
            $this->db->setSiteState((int) $site->id, $key, $new);
        }
    }

    private function checkAdmins(Site $site, ScanResult $result, \PDO $pdo, string $p, int $now, bool $first): void
    {
        $st = $pdo->prepare("SELECT u.user_login FROM {$p}users u JOIN {$p}usermeta m ON m.user_id = u.ID
            WHERE m.meta_key = ? AND m.meta_value LIKE ? ORDER BY u.user_login");
        $st->execute(["{$p}capabilities", '%"administrator"%']);
        $current = array_map('strval', $st->fetchAll(\PDO::FETCH_COLUMN));
        $stored = $this->db->siteState((int) $site->id, 'admins');
        $this->db->setSiteState((int) $site->id, 'admins', json_encode($current, JSON_UNESCAPED_UNICODE));
        if ($first || $stored === null) {
            return;
        }
        $known = json_decode($stored, true) ?: [];
        foreach (array_diff($current, $known) as $login) {
            $this->record($site, $result, new Finding(
                Finding::ADDED, "db:users/{$login}", Severity::Critical, 'db-admin',
                "管理者アカウントが増えています: {$login}", hash('sha256', $login), null,
            ), $now);
        }
        foreach (array_diff($known, $current) as $login) {
            $this->record($site, $result, new Finding(
                Finding::DELETED, "db:users/{$login}", Severity::Warning, 'db-admin-removed',
                "管理者アカウントが削除または降格されました: {$login}", hash('sha256', $login), null,
            ), $now);
        }
    }

    private function inspect(Site $site, ScanResult $result, string $path, string $label, string $value, string $ownHost, int $now, bool $first): void
    {
        foreach (self::RULES as [$rule, $sev, $desc, $re]) {
            if (preg_match($re, $value, $m, PREG_OFFSET_CAPTURE)) {
                $snippet = self::excerpt($value, (int) $m[0][1]);
                $this->recordOnce($site, $result, new Finding(
                    $first ? Finding::EXISTING : Finding::ADDED, $path, Severity::from($sev), $rule,
                    "{$label}に{$desc}が埋め込まれています", hash('sha256', $rule . $snippet), $snippet,
                ), $now);
                return;
            }
        }

        if (preg_match_all(self::EXTERNAL_SCRIPT, $value, $all, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($all as $m) {
                $host = strtolower($m[1][0]);
                if ($this->allowed($host, $ownHost)) {
                    continue;
                }
                $snippet = self::excerpt($value, (int) $m[0][1]);
                $this->recordOnce($site, $result, new Finding(
                    $first ? Finding::EXISTING : Finding::ADDED, $path,
                    // The first scan only records what is already there (analytics, ads, ...).
                    $first ? Severity::Info : Severity::Warning, 'script-external',
                    "{$label}に外部のスクリプト ({$host}) が埋め込まれています", hash('sha256', 'script-external' . $host), $snippet,
                ), $now);
            }
        }
    }

    private function allowed(string $host, string $ownHost): bool
    {
        if ($host === $ownHost || ($ownHost !== '' && str_ends_with($host, '.' . $ownHost))) {
            return true;
        }
        foreach ($this->allowDomains as $d) {
            $d = strtolower(ltrim((string) $d, '.'));
            if ($host === $d || str_ends_with($host, '.' . $d)) {
                return true;
            }
        }
        return false;
    }

    /** Record only if this exact problem (same place, same content, same rule) was not recorded before. */
    private function recordOnce(Site $site, ScanResult $result, Finding $f, int $now): void
    {
        if (!$this->db->hasFinding((int) $site->id, $f->path, $f->sha256, $f->rule)) {
            $this->record($site, $result, $f, $now);
        }
    }

    private function record(Site $site, ScanResult $result, Finding $f, int $now): void
    {
        $f->id = $this->db->addFinding((int) $site->id, $f, $now);
        $result->findings[] = $f;
    }

    private static function excerpt(string $s, int $offset): string
    {
        $part = preg_replace('/\s+/', ' ', substr($s, max(0, $offset), 160)) ?? '';
        return mb_convert_encoding(mb_strcut($part, 0, 100, 'UTF-8'), 'UTF-8', 'UTF-8');
    }
}
