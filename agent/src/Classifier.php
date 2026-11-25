<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Decides how serious a file change is from its location and type.
 * Content-based checks (malware patterns, official checksums) come in a later step.
 */
final class Classifier
{
    private const EXEC_RE = '/\.(php[0-9]?|phtml|pht|phar|phps|inc)$/i';

    private const CONFIG_FILES = ['.htaccess', '.user.ini', 'php.ini'];

    private const DROPINS = [
        'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php',
        'object-cache.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php',
        'fatal-error-handler.php', 'php-error.php',
    ];

    private const CORE_ROOT_FILES = [
        'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config.php',
        'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
        'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
    ];

    private const VERBS = [
        Finding::ADDED => '作成',
        Finding::MODIFIED => '変更',
        Finding::DELETED => '削除',
    ];

    public function classify(string $kind, string $path, string $type, ?string $sha256): Finding
    {
        [$severity, $rule, $what] = $this->decide($kind, $path, $type);
        $message = sprintf('%sが%sされました', $what, self::VERBS[$kind]);
        return new Finding($kind, $path, $severity, $rule, $message, $sha256);
    }

    /** @return array{Severity,string,string} */
    private function decide(string $kind, string $path, string $type): array
    {
        $base = basename($path);
        $exec = (bool) preg_match(self::EXEC_RE, $base);
        $deleted = $kind === Finding::DELETED;

        if (in_array($base, self::CONFIG_FILES, true)) {
            return [Severity::Critical, 'server-config', "サーバー設定ファイル ({$base}) "];
        }
        if ($path === 'wp-config.php') {
            return [Severity::Critical, 'wp-config', 'wp-config.php '];
        }
        if (str_starts_with($path, 'wp-content/uploads/') && $exec) {
            return [$deleted ? Severity::Warning : Severity::Critical, 'uploads-php', 'uploads 内の PHP ファイル'];
        }
        if (str_starts_with($path, 'wp-content/mu-plugins/')) {
            return [Severity::Critical, 'mu-plugin', 'mu-plugins 内のファイル'];
        }
        if (str_starts_with($path, 'wp-content/') && substr_count($path, '/') === 1 && in_array($base, self::DROPINS, true)) {
            return [Severity::Critical, 'dropin', "drop-in ({$base}) "];
        }
        if ($type === FileWalker::TYPE_LINK) {
            return [Severity::Warning, 'symlink', 'シンボリックリンク'];
        }
        if ($exec && !str_contains($path, '/') && !in_array($base, self::CORE_ROOT_FILES, true)) {
            return match ($kind) {
                Finding::ADDED => [Severity::Critical, 'root-php', '公開ディレクトリ直下の見慣れない PHP ファイル'],
                Finding::MODIFIED => [Severity::Warning, 'root-php', '公開ディレクトリ直下の PHP ファイル'],
                default => [Severity::Info, 'root-php', '公開ディレクトリ直下の PHP ファイル'],
            };
        }
        if (str_starts_with($path, 'wp-admin/') || str_starts_with($path, 'wp-includes/')
            || (!str_contains($path, '/') && in_array($base, self::CORE_ROOT_FILES, true))) {
            return [Severity::Warning, 'core', 'WordPress コアファイル'];
        }
        if (str_starts_with($path, 'wp-content/uploads/')) {
            return [Severity::Info, 'uploads', 'アップロードファイル'];
        }
        if ($exec || preg_match('/\.(js|html?|svg)$/i', $base)) {
            $where = match (true) {
                str_starts_with($path, 'wp-content/plugins/') => 'プラグインのファイル',
                str_starts_with($path, 'wp-content/themes/') => 'テーマのファイル',
                default => 'プログラムファイル',
            };
            return [$deleted ? Severity::Info : Severity::Warning, 'code', $where];
        }
        return [Severity::Info, 'other', 'ファイル'];
    }
}
