<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Finds WordPress installs under the configured roots.
 *
 * A directory counts as a WordPress install when it has wp-includes/version.php
 * and wp-content/. No PHP from the site is ever executed; files are only read.
 */
final class SiteDiscovery
{
    private const SKIP_DIRS = ['wp-content', 'wp-includes', 'wp-admin', 'node_modules', '.git', 'vendor'];
    private const NAME_SUFFIXES = ['public_html', 'htdocs', 'html', 'www', 'public', 'wordpress'];

    /**
     * @param string[] $roots
     * @param array<string,string> $nameOverrides absolute path => display name
     */
    public function __construct(
        private array $roots,
        private int $maxDepth,
        private array $nameOverrides,
        private Logger $logger,
    ) {
    }

    /** @return array<string,Site> keyed by site name, sorted */
    public function discover(): array
    {
        $found = [];
        foreach ($this->roots as $root) {
            $real = realpath((string) $root);
            if ($real === false || !is_dir($real)) {
                $this->logger->warning("監視ルートが見つかりません: {$root}");
                continue;
            }
            $this->walk($real, $real, 0, $found);
        }

        $sites = [];
        foreach ($found as $path => $root) {
            $name = $this->nameOverrides[$path] ?? self::defaultName($path, $root);
            if (isset($sites[$name])) {
                $rel = $path === $root ? basename($root) : substr($path, strlen($root) + 1);
                $name = $rel;
            }
            if (isset($sites[$name])) {
                $name = $path;
            }
            [$version, $locale] = self::readVersion($path);
            $sites[$name] = new Site($path, $name, $version, null, $locale);
        }
        ksort($sites, SORT_STRING);
        return $sites;
    }

    /** @param array<string,string> $found */
    private function walk(string $dir, string $root, int $depth, array &$found): void
    {
        if (is_file("{$dir}/wp-includes/version.php") && is_dir("{$dir}/wp-content")) {
            $found[$dir] = $root;
            // Keep descending: a site can have another WordPress in a subdirectory (e.g. /blog).
        }
        if ($depth >= $this->maxDepth) {
            return;
        }
        $h = @opendir($dir);
        if ($h === false) {
            $this->logger->warning("ディレクトリを読めません: {$dir}");
            return;
        }
        $children = [];
        while (($entry = readdir($h)) !== false) {
            if ($entry === '.' || $entry === '..' || in_array($entry, self::SKIP_DIRS, true)) {
                continue;
            }
            $path = "{$dir}/{$entry}";
            if (!is_link($path) && is_dir($path)) {
                $children[] = $path;
            }
        }
        closedir($h);
        foreach ($children as $child) {
            $this->walk($child, $root, $depth + 1, $found);
        }
    }

    private static function defaultName(string $path, string $root): string
    {
        if ($path === $root) {
            return basename($root);
        }
        $parts = explode('/', substr($path, strlen($root) + 1));
        while (count($parts) > 1 && in_array(end($parts), self::NAME_SUFFIXES, true)) {
            array_pop($parts);
        }
        return implode('/', $parts);
    }

    /** @return array{?string,?string} version, locale of localized builds (e.g. ja) */
    private static function readVersion(string $path): array
    {
        $src = @file_get_contents("{$path}/wp-includes/version.php", false, null, 0, 64 * 1024);
        if ($src === false) {
            return [null, null];
        }
        $version = preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $src, $m) ? $m[1] : null;
        $locale = preg_match('/\$wp_local_package\s*=\s*[\'"]([^\'"]+)[\'"]/', $src, $m) ? $m[1] : null;
        return [$version, $locale];
    }
}
