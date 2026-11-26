<?php

namespace WPGuard\Sentinel;

/**
 * Sends messages to Slack at the end of the request, so visitors never wait for Slack.
 * Messages that fail to send are kept and retried on a later request.
 */
final class Notifier
{
    public const CRITICAL = 'critical';
    public const WARNING = 'warning';
    public const INFO = 'info';

    private const PENDING_OPTION = 'wpguard_pending_notifications';
    private const MAX_PENDING = 50;
    private const RETRY_INTERVAL = 300;

    private const LABELS = [
        self::CRITICAL => ['🔴', '緊急'],
        self::WARNING => ['🟡', '警告'],
        self::INFO => ['🔵', '情報'],
    ];

    /** @var Config|null */
    private static $config = null;
    /** @var array<int,array{severity:string,text:string}> */
    private static $queue = [];
    /** @var bool */
    private static $hooked = false;

    public static function init(Config $config): void
    {
        self::$config = $config;
        add_action('shutdown', [self::class, 'flush'], PHP_INT_MAX);
    }

    /** @param string[] $lines already formatted lines (use esc() for anything user-controlled) */
    public static function send(string $severity, string $title, array $lines = []): void
    {
        if (self::$config === null || ($severity === self::INFO && !self::$config->notifyInfo)) {
            return;
        }
        [$emoji, $label] = self::LABELS[$severity];
        $header = sprintf('%s *[%s] %s*', $emoji, $label, self::esc(self::siteName()));
        if ($severity === self::CRITICAL && self::$config->mention !== '') {
            $header .= ' ' . self::$config->mention;
        }
        $text = $header . "\n*" . self::esc($title) . '*';
        foreach ($lines as $line) {
            $text .= "\n" . $line;
        }
        $text .= "\n🕐 " . self::date('Y-m-d H:i');
        self::$queue[] = ['severity' => $severity, 'text' => $text];
    }

    /** Formats a time in the notification time zone (WPGUARD_TIMEZONE), not the site's setting. */
    public static function date(string $format, ?int $timestamp = null): string
    {
        try {
            $tz = new \DateTimeZone(self::$config !== null ? self::$config->timezone : 'Asia/Tokyo');
        } catch (\Exception $e) {
            $tz = wp_timezone();
        }
        return (string) wp_date($format, $timestamp, $tz);
    }

    /** Standard "who did it" line. */
    public static function actorLine(): string
    {
        $user = wp_get_current_user();
        if ($user && $user->exists()) {
            $who = self::esc($user->user_login);
        } elseif (defined('WP_CLI') && WP_CLI) {
            $who = 'WP-CLI';
        } elseif (wp_doing_cron()) {
            $who = 'WP-Cron';
        } else {
            $who = 'ログインしていない状態';
        }
        return sprintf('🛠️ 操作した人: %s  🌐 IP: `%s`', $who, self::esc(ClientIp::get()));
    }

    public static function flush(): void
    {
        if (self::$config === null) {
            return;
        }
        $messages = self::$queue;
        self::$queue = [];

        $pending = get_option(self::PENDING_OPTION, []);
        if (is_array($pending) && $pending !== [] && !get_transient('wpguard_retry_lock')) {
            set_transient('wpguard_retry_lock', 1, self::RETRY_INTERVAL);
            $messages = array_merge($pending, $messages);
            $pending = [];
        } elseif (!is_array($pending)) {
            $pending = [];
        }
        if ($messages === []) {
            return;
        }
        if (self::$config->webhook === '') {
            error_log('[WPGuard] WPGUARD_SLACK_WEBHOOK が設定されていないため、通知を送れません');
            return;
        }

        // Let the visitor go before talking to Slack (PHP-FPM only).
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }

        $failed = [];
        foreach ($messages as $m) {
            $res = wp_remote_post(self::$config->webhook, [
                'timeout' => 5,
                'headers' => ['Content-Type' => 'application/json; charset=utf-8'],
                'body' => wp_json_encode(['text' => $m['text'], 'unfurl_links' => false, 'unfurl_media' => false]),
            ]);
            if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
                $failed[] = $m;
            }
        }

        $all = array_slice(array_merge($pending, $failed), -self::MAX_PENDING);
        if ($all !== [] || get_option(self::PENDING_OPTION, null) !== null) {
            update_option(self::PENDING_OPTION, $all, false);
        }
        if ($failed !== []) {
            set_transient('wpguard_retry_lock', 1, self::RETRY_INTERVAL);
            error_log(sprintf('[WPGuard] Slack への送信に失敗しました (%d 件、後で再送します)', count($failed)));
        }
    }

    /** Escapes Slack control characters so user-controlled text cannot inject mentions or links. */
    public static function esc(string $s): string
    {
        return str_replace(['&', '<', '>', '`'], ['&amp;', '&lt;', '&gt;', "'"], $s);
    }

    private static function siteName(): string
    {
        if (self::$config !== null && self::$config->siteName !== '') {
            return self::$config->siteName;
        }
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        return is_string($host) && $host !== '' ? $host : get_bloginfo('name');
    }

    /** For tests. */
    public static function queued(): array
    {
        return self::$queue;
    }
}
