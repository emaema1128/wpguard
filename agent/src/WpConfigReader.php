<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Reads the database settings from wp-config.php without executing it.
 *
 * Uses PHP's tokenizer, so commented-out lines and strings that merely contain
 * "define(" are not mistaken for real settings.
 */
final class WpConfigReader
{
    /** @return array{name:string,user:string,password:string,host:string,charset:string,prefix:string}|null */
    public static function read(string $sitePath): ?array
    {
        $file = self::locate($sitePath);
        if ($file === null) {
            return null;
        }
        $src = @file_get_contents($file, false, null, 0, 512 * 1024);
        if ($src === false) {
            return null;
        }
        $values = self::parse($src);
        if (!isset($values['DB_NAME'], $values['DB_USER'], $values['DB_PASSWORD'], $values['DB_HOST'])) {
            return null;
        }
        return [
            'name' => $values['DB_NAME'],
            'user' => $values['DB_USER'],
            'password' => $values['DB_PASSWORD'],
            'host' => $values['DB_HOST'],
            'charset' => $values['DB_CHARSET'] ?? 'utf8mb4',
            'prefix' => $values['$table_prefix'] ?? 'wp_',
        ];
    }

    /** WordPress also accepts wp-config.php one directory above, if that directory is not another install. */
    private static function locate(string $sitePath): ?string
    {
        if (is_file("{$sitePath}/wp-config.php")) {
            return "{$sitePath}/wp-config.php";
        }
        $parent = dirname($sitePath);
        if (is_file("{$parent}/wp-config.php") && !is_file("{$parent}/wp-settings.php")) {
            return "{$parent}/wp-config.php";
        }
        return null;
    }

    /** @return array<string,string> constant name (or '$table_prefix') => string value */
    public static function parse(string $src): array
    {
        $tokens = array_values(array_filter(
            token_get_all($src),
            static fn ($t) => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
        $out = [];
        $n = count($tokens);
        for ($i = 0; $i < $n; $i++) {
            $t = $tokens[$i];
            // define( 'NAME', 'value' )
            if (is_array($t) && $t[0] === T_STRING && strtolower($t[1]) === 'define'
                && ($tokens[$i + 1] ?? null) === '('
                && self::isString($tokens[$i + 2] ?? null)
                && ($tokens[$i + 3] ?? null) === ','
                && self::isString($tokens[$i + 4] ?? null)
                && in_array($tokens[$i + 5] ?? null, [')', ','], true)) {
                $out[self::unquote($tokens[$i + 2][1])] ??= self::unquote($tokens[$i + 4][1]);
                $i += 5;
                continue;
            }
            // $table_prefix = 'wp_';
            if (is_array($t) && $t[0] === T_VARIABLE && $t[1] === '$table_prefix'
                && ($tokens[$i + 1] ?? null) === '='
                && self::isString($tokens[$i + 2] ?? null)
                && ($tokens[$i + 3] ?? null) === ';') {
                $out['$table_prefix'] = self::unquote($tokens[$i + 2][1]);
                $i += 3;
            }
        }
        return $out;
    }

    private static function isString(mixed $t): bool
    {
        return is_array($t) && $t[0] === T_CONSTANT_ENCAPSED_STRING;
    }

    private static function unquote(string $literal): string
    {
        $q = $literal[0];
        $body = substr($literal, 1, -1);
        return $q === "'" ? str_replace(["\\'", '\\\\'], ["'", '\\'], $body) : stripcslashes($body);
    }

    /** PDO DSN for WordPress's DB_HOST forms: host, host:port, host:/path/to.sock, :/path/to.sock */
    public static function dsn(array $c): string
    {
        $host = $c['host'];
        $parts = ['dbname=' . $c['name'], 'charset=' . preg_replace('/[^A-Za-z0-9_]/', '', $c['charset'])];
        if (preg_match('#^([^:]*):(/.+)$#', $host, $m)) {
            $parts[] = 'unix_socket=' . $m[2];
        } elseif (preg_match('#^(.+):(\d+)$#', $host, $m)) {
            $parts[] = 'host=' . $m[1];
            $parts[] = 'port=' . $m[2];
        } elseif ($host === 'localhost' || $host === '') {
            // Same as mysqli in WordPress: "localhost" means the local socket.
            $parts[] = 'host=localhost';
        } else {
            $parts[] = 'host=' . $host;
        }
        return 'mysql:' . implode(';', $parts);
    }
}
