<?php

namespace WPGuard\Sentinel;

/**
 * P-10: security headers for every page (front end, admin, login, REST API).
 *
 * Only headers that are safe for almost every WordPress site are on by default.
 * A full Content-Security-Policy would break most themes and plugins, so only the
 * parts that do not restrict scripts are sent. HSTS is off by default: once a browser
 * has seen it, a lapsed certificate makes the site unreachable.
 * A header already set (e.g. by Apache) is never sent twice.
 */
final class SecurityHeaders
{
    /** @var Config */
    private static $config;

    public static function register(Config $config): void
    {
        self::$config = $config;
        if (!$config->securityHeaders) {
            return;
        }
        add_action('init', [self::class, 'send'], 1);
        // The generator tag and feeds reveal the exact WordPress version.
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string');
    }

    /** @return array<string,string> header name => value */
    public static function headers(): array
    {
        $c = self::$config;
        $h = [
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
        ];
        if ($c->frameOptions !== '') {
            $h['X-Frame-Options'] = $c->frameOptions;
        }
        $csp = ["base-uri 'self'", "object-src 'none'"];
        if ($c->frameOptions === 'SAMEORIGIN') {
            $csp[] = "frame-ancestors 'self'";
        } elseif ($c->frameOptions === 'DENY') {
            $csp[] = "frame-ancestors 'none'";
        }
        $h['Content-Security-Policy'] = implode('; ', $csp);
        if ($c->permissionsPolicy !== '') {
            $h['Permissions-Policy'] = $c->permissionsPolicy;
        }
        if ($c->hsts > 0 && is_ssl()) {
            $h['Strict-Transport-Security'] = 'max-age=' . $c->hsts;
        }
        return $h;
    }

    public static function send(): void
    {
        if (headers_sent() || PHP_SAPI === 'cli') {
            return;
        }
        $already = [];
        foreach (headers_list() as $line) {
            $already[strtolower(trim(strtok($line, ':')))] = true;
        }
        foreach (self::headers() as $name => $value) {
            if (!isset($already[strtolower($name)])) {
                header($name . ': ' . $value);
            }
        }
        header_remove('X-Powered-By');
    }
}
