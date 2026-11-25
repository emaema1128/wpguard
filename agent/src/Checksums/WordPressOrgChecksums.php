<?php

declare(strict_types=1);

namespace WPGuard\Checksums;

use WPGuard\Database;
use WPGuard\Logger;

/**
 * Fetches checksums from wordpress.org and caches them in the state database.
 * A release never changes, so results are kept for a long time; "not found"
 * (e.g. premium plugins) is remembered for a week. Network errors are not cached,
 * and after the first one the rest of the run skips the network.
 */
final class WordPressOrgChecksums implements ChecksumProvider
{
    private const CORE_URL = 'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s';
    private const PLUGIN_URL = 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json';
    private const FOUND_TTL = 30 * 86400;
    private const NOT_FOUND_TTL = 7 * 86400;
    private const SAFE = '/^[A-Za-z0-9._-]{1,100}$/';

    private bool $offline = false;
    /** @var array<string,?array> */
    private array $memo = [];

    public function __construct(private Database $db, private Logger $logger, private int $timeout)
    {
        if (!extension_loaded('curl')) {
            throw new \RuntimeException('チェックサムの取得には PHP の curl 拡張モジュールが必要です');
        }
    }

    public function core(string $version, string $locale): ?array
    {
        if (!preg_match(self::SAFE, $version) || !preg_match(self::SAFE, $locale)) {
            return null;
        }
        return $this->get("core:{$version}:{$locale}", sprintf(self::CORE_URL, rawurlencode($version), rawurlencode($locale)), static function (array $json): ?array {
            if (!isset($json['checksums']) || !is_array($json['checksums'])) {
                return null;
            }
            $out = [];
            foreach ($json['checksums'] as $path => $md5) {
                if (is_string($md5)) {
                    $out[(string) $path] = strtolower($md5);
                }
            }
            return $out === [] ? null : $out;
        });
    }

    public function plugin(string $slug, string $version): ?array
    {
        if (!preg_match(self::SAFE, $slug) || !preg_match(self::SAFE, $version)) {
            return null;
        }
        return $this->get("plugin:{$slug}:{$version}", sprintf(self::PLUGIN_URL, rawurlencode($slug), rawurlencode($version)), static function (array $json): ?array {
            if (!isset($json['files']) || !is_array($json['files'])) {
                return null;
            }
            $out = [];
            foreach ($json['files'] as $path => $sums) {
                // sha256 is a string, or a list when the file differs between builds of the same version.
                $sha = array_map('strtolower', array_filter((array) ($sums['sha256'] ?? []), 'is_string'));
                if ($sha !== []) {
                    $out[(string) $path] = array_values($sha);
                }
            }
            return $out === [] ? null : $out;
        });
    }

    /** @param callable(array):?array $parse */
    private function get(string $key, string $url, callable $parse): ?array
    {
        if (array_key_exists($key, $this->memo)) {
            return $this->memo[$key];
        }
        $now = time();
        $cached = $this->db->cacheGet($key);
        if ($cached !== null) {
            $ttl = $cached['body'] === null ? self::NOT_FOUND_TTL : self::FOUND_TTL;
            if ($cached['fetched_at'] >= $now - $ttl) {
                return $this->memo[$key] = $cached['body'] === null ? null : $parse(json_decode($cached['body'], true) ?: []);
            }
        }
        if ($this->offline) {
            return $this->memo[$key] = null;
        }

        [$status, $body] = $this->fetch($url);
        if ($status === 200) {
            $json = json_decode((string) $body, true);
            $data = is_array($json) ? $parse($json) : null;
            $this->db->cachePut($key, $data === null ? null : (string) $body, $now);
            return $this->memo[$key] = $data;
        }
        if ($status === 404) {
            $this->db->cachePut($key, null, $now);
            return $this->memo[$key] = null;
        }

        $this->offline = true;
        $this->logger->warning(sprintf(
            '公式チェックサムを取得できません (HTTP %d)。今回のスキャンでは照合を行いません: %s%s',
            $status, $url, $status === 403 ? ' — サンドボックスやファイアウォールで通信が許可されているか確認してください' : '',
        ));
        return $this->memo[$key] = null;
    }

    /** @return array{int,?string} */
    private function fetch(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => 'WPGuard',
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        return [$body === false ? 0 : $status, $body === false ? null : (string) $body];
    }
}
