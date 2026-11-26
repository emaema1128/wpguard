<?php

declare(strict_types=1);

namespace WPGuard;

use WPGuard\Checksums\ChecksumProvider;

/**
 * Compares files with the official WordPress / plugin releases.
 *
 * MATCH    the file is byte-identical to the official release (a legitimate install or update)
 * MISMATCH the official release has this file, but with different contents
 * EXTRA    the file sits in an official directory but the release has no such file
 * null     nothing to compare with (premium plugin, themes, network unavailable, ...)
 */
final class OfficialVerifier
{
    public const MATCH = 'match';
    public const MISMATCH = 'mismatch';
    public const EXTRA = 'extra';

    public const SENTINEL_PREFIX = 'wp-content/mu-plugins/wpguard-sentinel';
    public const UPLOADS_HTACCESS = 'wp-content/uploads/.htaccess';
    /** The rules WPGuard Sentinel writes to uploads/.htaccess (comments around them vary by language). */
    private const SENTINEL_HTACCESS = [
        '<FilesMatch "\.(?i:php[0-9]?|phtml|pht|phar|phps|inc)$">',
        'Require all denied',
        '</FilesMatch>',
    ];

    /** @var array<string,string>|null relative path inside mu-plugins => sha256 */
    private ?array $manifest = null;

    private ?Site $site = null;
    private ?array $core = null;
    private bool $coreLoaded = false;
    /** @var array<string,?array> slug => checksums */
    private array $plugins = [];

    public function __construct(private ChecksumProvider $provider, private string $manifestFile = '')
    {
    }

    public static function isSentinel(string $rel): bool
    {
        return $rel === self::SENTINEL_PREFIX . '.php' || str_starts_with($rel, self::SENTINEL_PREFIX . '/');
    }

    /** @return array<string,string>|null */
    private function manifest(): ?array
    {
        if ($this->manifest === null) {
            $this->manifest = [];
            $lines = $this->manifestFile !== '' ? @file($this->manifestFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : false;
            foreach ($lines ?: [] as $line) {
                if (preg_match('/^([a-f0-9]{64})\s+\*?(.+)$/', $line, $m)) {
                    $this->manifest[$m[2]] = $m[1];
                }
            }
        }
        return $this->manifest === [] ? null : $this->manifest;
    }

    private static function isSentinelHtaccess(string $abs): bool
    {
        $src = @file_get_contents($abs, false, null, 0, 64 * 1024);
        if ($src === false) {
            return false;
        }
        $rules = [];
        // Not \R: without the u flag it also splits on byte 0x85, which occurs inside Japanese characters.
        foreach (preg_split('/\r\n|\n|\r/', $src) ?: [] as $line) {
            $line = trim($line);
            if ($line !== '' && $line[0] !== '#') {
                $rules[] = $line;
            }
        }
        return $rules === self::SENTINEL_HTACCESS;
    }

    public function forSite(Site $site): void
    {
        $this->site = $site;
        $this->core = null;
        $this->coreLoaded = false;
        $this->plugins = [];
    }

    public static function isCoreDir(string $rel): bool
    {
        return str_starts_with($rel, 'wp-admin/') || str_starts_with($rel, 'wp-includes/');
    }

    public function verify(string $rel, string $abs, ?string $sha256): ?string
    {
        if ($this->site === null) {
            return null;
        }

        if (self::isSentinel($rel)) {
            $manifest = $this->manifest();
            if ($manifest === null) {
                return null; // installed without plugin/install.sh: judged by location as before
            }
            $key = substr($rel, strlen('wp-content/mu-plugins/'));
            if (!isset($manifest[$key])) {
                return self::EXTRA;
            }
            return $sha256 !== null && hash_equals($manifest[$key], $sha256) ? self::MATCH : self::MISMATCH;
        }
        if ($rel === self::UPLOADS_HTACCESS && self::isSentinelHtaccess($abs)) {
            return self::MATCH;
        }

        if (preg_match('#^wp-content/plugins/([^/]+)/(.+)$#', $rel, $m)) {
            $sums = $this->pluginChecksums($m[1]);
            if ($sums === null) {
                return null;
            }
            if (!isset($sums[$m[2]])) {
                return self::EXTRA;
            }
            return $sha256 !== null && in_array($sha256, $sums[$m[2]], true) ? self::MATCH : self::MISMATCH;
        }

        $core = $this->coreChecksums();
        if ($core === null) {
            return null;
        }
        if (isset($core[$rel])) {
            $md5 = @md5_file($abs);
            if ($md5 === $core[$rel]) {
                return self::MATCH;
            }
            // Bundled themes and plugins (akismet, twenty*) are updated separately from core.
            return str_starts_with($rel, 'wp-content/') ? null : self::MISMATCH;
        }
        return self::isCoreDir($rel) ? self::EXTRA : null;
    }

    private function coreChecksums(): ?array
    {
        if (!$this->coreLoaded) {
            $this->coreLoaded = true;
            $v = $this->site->wpVersion;
            $this->core = $v === null ? null : $this->provider->core($v, $this->site->locale ?? 'en_US');
        }
        return $this->core;
    }

    private function pluginChecksums(string $slug): ?array
    {
        if (!array_key_exists($slug, $this->plugins)) {
            $version = self::pluginVersion($this->site->path . '/wp-content/plugins/' . $slug);
            $this->plugins[$slug] = $version === null ? null : $this->provider->plugin($slug, $version);
        }
        return $this->plugins[$slug];
    }

    /** Reads the Version header of the plugin's main file, without executing it. */
    public static function pluginVersion(string $dir): ?string
    {
        $files = @glob($dir . '/*.php') ?: [];
        sort($files, SORT_STRING);
        foreach ($files as $file) {
            if (is_link($file)) {
                continue;
            }
            $head = @file_get_contents($file, false, null, 0, 8192);
            if ($head === false || !preg_match('/^[ \t\/*#@]*Plugin Name\s*:/mi', $head)) {
                continue;
            }
            if (preg_match('/^[ \t\/*#@]*Version\s*:\s*([^\s*]+)/mi', $head, $m)) {
                return $m[1];
            }
            return null;
        }
        return null;
    }
}
