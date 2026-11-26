<?php

namespace WPGuard\Sentinel;

/**
 * P-08: reports new WP-Cron events.
 *
 * Malware often schedules a job that puts the backdoor back after it was removed.
 * Every few minutes the list of scheduled hooks is compared with the known list; for a
 * new hook we look up where the code that handles it lives:
 *   - core or a normal plugin / theme          → recorded only (plugins add jobs all the time)
 *   - mu-plugins                               → 🟡
 *   - uploads, eval()'d code, anywhere else    → 🔴
 *   - no handler found                         → 🟡 (left over, or loaded some other way)
 * Suspicious arguments (URLs, base64, eval ...) or random-looking names make it 🔴.
 */
final class CronMonitor
{
    private const KNOWN_OPTION = 'wpguard_known_cron_hooks';
    private const CHECK_INTERVAL = 300;
    private const SUSPICIOUS_ARGS = '/(eval\s*\(|base64_decode|gzinflate|str_rot13|<\?php|https?:\/\/|\$_(GET|POST|REQUEST|COOKIE))/i';
    private const RANDOM_NAME = '/^[a-f0-9_]{12,}$|^[a-z0-9]{20,}$/i';

    public static function register(): void
    {
        // Late on init, after plugins and themes have attached their handlers.
        add_action('init', [self::class, 'maybeCheck'], 999);
    }

    public static function maybeCheck(): void
    {
        if (get_transient('wpguard_cron_check')) {
            return;
        }
        set_transient('wpguard_cron_check', 1, self::CHECK_INTERVAL);
        self::check();
    }

    public static function check(): void
    {
        $events = self::events();
        $known = get_option(self::KNOWN_OPTION, null);
        $current = array_keys($events);
        sort($current);

        if (!is_array($known)) {
            update_option(self::KNOWN_OPTION, $current, false);
            return;
        }
        $new = array_diff($current, $known);
        if ($new === []) {
            if (count($current) !== count($known)) {
                update_option(self::KNOWN_OPTION, $current, false); // some hooks went away
            }
            return;
        }

        foreach ($new as $hook) {
            self::report($hook, $events[$hook]);
        }
        update_option(self::KNOWN_OPTION, array_values(array_unique(array_merge($known, $current))), false);
    }

    /** @return array<string,array{next:int,schedule:string,interval:int,args:array}> hook => first event */
    private static function events(): array
    {
        $cron = function_exists('_get_cron_array') ? _get_cron_array() : get_option('cron');
        $out = [];
        if (!is_array($cron)) {
            return $out;
        }
        ksort($cron);
        foreach ($cron as $time => $hooks) {
            if (!is_array($hooks)) {
                continue;
            }
            foreach ($hooks as $hook => $instances) {
                if (isset($out[$hook]) || !is_array($instances)) {
                    continue;
                }
                $first = reset($instances);
                $out[(string) $hook] = [
                    'next' => (int) $time,
                    'schedule' => is_array($first) && !empty($first['schedule']) ? (string) $first['schedule'] : '',
                    'interval' => is_array($first) && isset($first['interval']) ? (int) $first['interval'] : 0,
                    'args' => is_array($first) && isset($first['args']) && is_array($first['args']) ? $first['args'] : [],
                ];
            }
        }
        return $out;
    }

    /** @param array{next:int,schedule:string,interval:int,args:array} $event */
    private static function report(string $hook, array $event): void
    {
        [$where, $kind] = self::handlerLocation($hook);
        $reasons = [];

        $argsText = self::argsText($event['args']);
        if ($argsText !== '' && preg_match(self::SUSPICIOUS_ARGS, $argsText)) {
            $reasons[] = '引数に URL やコードのような内容が含まれています';
        }
        if (preg_match(self::RANDOM_NAME, $hook)) {
            $reasons[] = '処理名がランダムな文字列です';
        }

        switch ($kind) {
            case 'core':
            case 'plugin':
            case 'theme':
                $severity = Notifier::INFO;
                break;
            case 'mu-plugin':
            case 'none':
                $severity = Notifier::WARNING;
                break;
            default:
                $severity = Notifier::CRITICAL;
                $reasons[] = $kind === 'eval' ? '処理が eval() で作られたコードです' : 'プラグイン・テーマ以外の場所にあるコードです';
        }
        if ($reasons !== [] && $kind !== 'core') {
            $severity = Notifier::CRITICAL;
        }

        $lines = [
            sprintf('⏰ 処理名: `%s`  🔁 %s  ⏭ 次回: %s', Notifier::esc($hook), self::scheduleLabel($event), Notifier::date('m/d H:i', $event['next'])),
            '📂 処理の場所: ' . $where,
        ];
        if ($argsText !== '') {
            $lines[] = '📦 引数: `' . Notifier::esc(mb_strimwidth($argsText, 0, 120, '…', 'UTF-8')) . '`';
        }
        foreach ($reasons as $r) {
            $lines[] = '⚠️ ' . $r;
        }
        if ($severity !== Notifier::INFO) {
            $lines[] = '心当たりがなければ、マルウェアが再感染のために登録した可能性があります。処理の場所のファイルを確認してください。';
        }
        Notifier::send($severity, '新しい定期実行の処理 (WP-Cron) が登録されました', $lines);
    }

    /**
     * Where the code handling a hook is, as [label for Slack, kind].
     * kind: core | plugin | theme | mu-plugin | uploads | eval | other | none
     *
     * @return array{string,string}
     */
    public static function handlerLocation(string $hook): array
    {
        global $wp_filter;
        if (!isset($wp_filter[$hook]) || !($wp_filter[$hook] instanceof \WP_Hook)) {
            return ['見つかりません (このサイトのコードに、この処理を受け持つものがありません)', 'none'];
        }
        $worst = null;
        foreach ($wp_filter[$hook]->callbacks as $callbacks) {
            foreach ($callbacks as $cb) {
                $loc = self::callbackFile($cb['function']);
                if ($loc === null) {
                    continue;
                }
                [$file, $line] = $loc;
                $kind = self::classify($file);
                $rank = ['core' => 0, 'plugin' => 1, 'theme' => 1, 'mu-plugin' => 2, 'other' => 3, 'uploads' => 4, 'eval' => 4][$kind];
                if ($worst === null || $rank > $worst[2]) {
                    $worst = [$file, $line, $rank, $kind];
                }
            }
        }
        if ($worst === null) {
            return ['見つかりません', 'none'];
        }
        [$file, $line, , $kind] = $worst;
        $label = '`' . Notifier::esc(self::relative($file)) . ($line > 0 ? ":{$line}" : '') . '`';
        if ($kind === 'plugin' && preg_match('#^' . preg_quote(wp_normalize_path(WP_PLUGIN_DIR), '#') . '/([^/]+)#', wp_normalize_path($file), $m)) {
            $label .= ' (プラグイン ' . Notifier::esc($m[1]) . ')';
        }
        return [$label, $kind];
    }

    /** @return array{string,int}|null */
    private static function callbackFile($fn): ?array
    {
        try {
            if ($fn instanceof \Closure || (is_string($fn) && function_exists($fn))) {
                $r = new \ReflectionFunction($fn);
            } elseif (is_string($fn) && strpos($fn, '::') !== false) {
                $r = new \ReflectionMethod($fn);
            } elseif (is_array($fn) && count($fn) === 2) {
                $r = new \ReflectionMethod($fn[0], (string) $fn[1]);
            } elseif (is_object($fn) && method_exists($fn, '__invoke')) {
                $r = new \ReflectionMethod($fn, '__invoke');
            } else {
                return null;
            }
        } catch (\ReflectionException $e) {
            return null;
        }
        $file = $r->getFileName();
        return $file === false ? null : [(string) $file, (int) $r->getStartLine()];
    }

    private static function classify(string $file): string
    {
        if (strpos($file, "eval()'d code") !== false || strpos($file, 'runtime-created function') !== false) {
            return 'eval';
        }
        $f = wp_normalize_path($file);
        $abs = wp_normalize_path(ABSPATH);
        $uploads = wp_upload_dir(null, false);
        $checks = [
            'uploads' => !empty($uploads['basedir']) ? wp_normalize_path($uploads['basedir']) . '/' : null,
            'mu-plugin' => wp_normalize_path(WPMU_PLUGIN_DIR) . '/',
            'plugin' => wp_normalize_path(WP_PLUGIN_DIR) . '/',
            'theme' => wp_normalize_path(get_theme_root()) . '/',
        ];
        foreach ($checks as $kind => $dir) {
            if ($dir !== null && strpos($f, $dir) === 0) {
                return $kind;
            }
        }
        if (strpos($f, $abs . 'wp-includes/') === 0 || strpos($f, $abs . 'wp-admin/') === 0) {
            return 'core';
        }
        return 'other';
    }

    private static function relative(string $file): string
    {
        $f = wp_normalize_path($file);
        $abs = wp_normalize_path(ABSPATH);
        return strpos($f, $abs) === 0 ? substr($f, strlen($abs)) : $f;
    }

    private static function argsText(array $args): string
    {
        if ($args === []) {
            return '';
        }
        $json = wp_json_encode($args, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return is_string($json) ? $json : '(表示できない値)';
    }

    /** @param array{schedule:string,interval:int} $event */
    private static function scheduleLabel(array $event): string
    {
        if ($event['schedule'] === '') {
            return '1 回だけ';
        }
        $i = $event['interval'];
        $every = $i >= 86400 && $i % 86400 === 0 ? ($i / 86400) . ' 日' : ($i >= 3600 && $i % 3600 === 0 ? ($i / 3600) . ' 時間' : max(1, (int) round($i / 60)) . ' 分');
        return sprintf('%sごと (%s)', $every, Notifier::esc($event['schedule']));
    }
}
