<?php

namespace WPGuard\Sentinel;

/**
 * The visitor's IP address.
 *
 * X-Forwarded-For is only believed when the request comes from a proxy listed in
 * WPGUARD_TRUSTED_PROXIES; otherwise an attacker could fake a new address on every
 * login attempt and never get locked out.
 */
final class ClientIp
{
    /** @var string[] */
    private static $trusted = [];
    /** @var string|null */
    private static $cached = null;

    /** @param string[] $trustedProxies */
    public static function configure(array $trustedProxies): void
    {
        self::$trusted = $trustedProxies;
        self::$cached = null;
    }

    public static function get(): string
    {
        if (self::$cached !== null) {
            return self::$cached;
        }
        $remote = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        $ip = self::valid($remote) ? $remote : '0.0.0.0';

        if (in_array($ip, self::$trusted, true) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $hops = array_reverse(array_map('trim', explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'])));
            foreach ($hops as $hop) {
                if (!self::valid($hop)) {
                    break;
                }
                $ip = $hop;
                if (!in_array($hop, self::$trusted, true)) {
                    break;
                }
            }
        }
        return self::$cached = $ip;
    }

    private static function valid(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}
