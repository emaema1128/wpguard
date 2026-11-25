<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Decides how serious a file change is.
 *
 * Inputs, strongest first:
 *   1. a malicious code pattern in the file
 *   2. comparison with the official release (identical / tampered / not part of it)
 *   3. where the file is (uploads, mu-plugins, .htaccess, ...)
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
        Finding::ADDED => '作成されました',
        Finding::MODIFIED => '変更されました',
        Finding::DELETED => '削除されました',
        Finding::EXISTING => '見つかりました',
    ];

    public static function isExecutable(string $basename): bool
    {
        return (bool) preg_match(self::EXEC_RE, $basename);
    }

    public function classify(
        string $kind,
        string $path,
        string $type,
        ?string $sha256,
        ?PatternMatch $match = null,
        ?string $official = null,
    ): Finding {
        [$severity, $rule, $what] = $this->byLocation($kind, $path, $type);
        $message = $what . 'が' . self::VERBS[$kind];
        $isPlugin = str_starts_with($path, 'wp-content/plugins/');

        if ($official === OfficialVerifier::MATCH) {
            [$severity, $rule, $message] = [Severity::Info, 'official', "{$message} (公式配布版と一致: 正規の更新)"];
        } elseif ($official === OfficialVerifier::MISMATCH) {
            [$severity, $rule, $message] = $isPlugin
                ? [Severity::max([$severity, Severity::Warning]), 'plugin-modified', 'プラグインのファイルが公式配布版と一致しません']
                : [Severity::Critical, 'core-modified', 'WordPress コアファイルが公式配布版と一致しません (改ざんの可能性)'];
        } elseif ($official === OfficialVerifier::EXTRA) {
            if ($isPlugin) {
                if (self::isExecutable(basename($path))) {
                    [$severity, $rule, $message] = [Severity::max([$severity, Severity::Warning]), 'plugin-extra', 'プラグインに、公式配布版にない PHP ファイルがあります'];
                }
            } else {
                [$severity, $rule, $message] = [Severity::Critical, 'core-extra', 'WordPress のコアディレクトリに、公式配布版にないファイルがあります'];
            }
        }

        $detail = null;
        if ($match !== null) {
            $severity = Severity::max([$severity, $match->severity]);
            $rule = $match->rule;
            $message = "怪しいコードが{$this->verbShort($kind)}: {$match->description}";
            $detail = $match->excerpt;
        }

        return new Finding($kind, $path, $severity, $rule, $message, $sha256, $detail);
    }

    private function verbShort(string $kind): string
    {
        return match ($kind) {
            Finding::ADDED => '含まれるファイルが作成されました',
            Finding::MODIFIED => '書き込まれました',
            default => '見つかりました',
        };
    }

    /** @return array{Severity,string,string} */
    private function byLocation(string $kind, string $path, string $type): array
    {
        $base = basename($path);
        $exec = self::isExecutable($base);
        $deleted = $kind === Finding::DELETED;
        $existing = $kind === Finding::EXISTING;

        if (in_array($base, self::CONFIG_FILES, true)) {
            return [$existing ? Severity::Info : Severity::Critical, 'server-config', "サーバー設定ファイル ({$base}) "];
        }
        if ($path === 'wp-config.php') {
            return [$existing ? Severity::Info : Severity::Critical, 'wp-config', 'wp-config.php '];
        }
        if (str_starts_with($path, 'wp-content/uploads/') && $exec) {
            // At baseline time the file may be harmless (some plugins drop an index.php), so ask for a look rather than raise the alarm.
            return [$deleted || $existing ? Severity::Warning : Severity::Critical, 'uploads-php', 'uploads 内の PHP ファイル'];
        }
        if (str_starts_with($path, 'wp-content/mu-plugins/')) {
            return [$existing ? Severity::Info : Severity::Critical, 'mu-plugin', 'mu-plugins 内のファイル'];
        }
        if (str_starts_with($path, 'wp-content/') && substr_count($path, '/') === 1 && in_array($base, self::DROPINS, true)) {
            return [$existing ? Severity::Info : Severity::Critical, 'dropin', "drop-in ({$base}) "];
        }
        if ($type === FileWalker::TYPE_LINK) {
            return [$existing ? Severity::Info : Severity::Warning, 'symlink', 'シンボリックリンク'];
        }
        if ($exec && !str_contains($path, '/') && !in_array($base, self::CORE_ROOT_FILES, true)) {
            return match ($kind) {
                Finding::ADDED => [Severity::Critical, 'root-php', '公開ディレクトリ直下の見慣れない PHP ファイル'],
                Finding::MODIFIED => [Severity::Warning, 'root-php', '公開ディレクトリ直下の PHP ファイル'],
                default => [Severity::Info, 'root-php', '公開ディレクトリ直下の PHP ファイル'],
            };
        }
        if (OfficialVerifier::isCoreDir($path) || (!str_contains($path, '/') && in_array($base, self::CORE_ROOT_FILES, true))) {
            return [$existing ? Severity::Info : Severity::Warning, 'core', 'WordPress コアファイル'];
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
            return [$deleted || $existing ? Severity::Info : Severity::Warning, 'code', $where];
        }
        return [Severity::Info, 'other', 'ファイル'];
    }
}
