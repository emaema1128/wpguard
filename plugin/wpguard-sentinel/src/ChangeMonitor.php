<?php

namespace WPGuard\Sentinel;

/**
 * P-03: reports plugin / theme installs, activations and updates.
 *
 * Activation is watched through the active_plugins option itself, so plugins switched
 * on by code (update_option) are caught too, not only clicks in the admin screen.
 */
final class ChangeMonitor
{
    public static function register(): void
    {
        add_action('update_option_active_plugins', [self::class, 'onActivePluginsChanged'], 10, 2);
        add_action('update_site_option_active_sitewide_plugins', [self::class, 'onSitewidePluginsChanged'], 10, 3);
        add_action('upgrader_process_complete', [self::class, 'onUpgrade'], 10, 2);
        add_action('switch_theme', [self::class, 'onSwitchTheme'], 10, 3);
        add_action('deleted_plugin', [self::class, 'onDeletedPlugin'], 10, 2);
    }

    public static function onActivePluginsChanged($old, $new): void
    {
        self::diff((array) $old, (array) $new);
    }

    public static function onSitewidePluginsChanged($option, $new, $old): void
    {
        self::diff(array_keys((array) $old), array_keys((array) $new));
    }

    /** @param string[] $old @param string[] $new */
    private static function diff(array $old, array $new): void
    {
        $activated = array_values(array_diff($new, $old));
        $deactivated = array_values(array_diff($old, $new));

        if ($activated !== []) {
            // Activation by someone who is not logged in (and not cron / WP-CLI) is what malware does.
            $anonymous = !is_user_logged_in() && !wp_doing_cron() && !(defined('WP_CLI') && WP_CLI);
            Notifier::send(
                $anonymous ? Notifier::CRITICAL : Notifier::WARNING,
                $anonymous ? 'ログインしていない状態でプラグインが有効化されました' : 'プラグインが有効化されました',
                [self::pluginList($activated), Notifier::actorLine()]
            );
        }
        if ($deactivated !== []) {
            Notifier::send(Notifier::INFO, 'プラグインが無効化されました', [self::pluginList($deactivated), Notifier::actorLine()]);
        }
    }

    /**
     * @param \WP_Upgrader $upgrader
     * @param array<string,mixed> $extra
     */
    public static function onUpgrade($upgrader, $extra): void
    {
        $type = isset($extra['type']) ? (string) $extra['type'] : '';
        $action = isset($extra['action']) ? (string) $extra['action'] : '';
        if (!in_array($type, ['plugin', 'theme', 'core'], true)) {
            return;
        }

        if ($type === 'core') {
            Notifier::send(Notifier::INFO, 'WordPress 本体が更新されました', ['📦 バージョン: ' . Notifier::esc(get_bloginfo('version')), Notifier::actorLine()]);
            return;
        }

        $names = [];
        if ($action === 'install') {
            $data = $type === 'plugin' ? ($upgrader->new_plugin_data ?? []) : ($upgrader->new_theme_data ?? []);
            $name = is_array($data) && !empty($data['Name']) ? (string) $data['Name'] : '';
            if ($name === '' && isset($upgrader->result['destination_name'])) {
                $name = (string) $upgrader->result['destination_name'];
            }
            $names[] = $name !== '' ? $name : '(不明)';
        } else {
            $items = $type === 'plugin' ? ($extra['plugins'] ?? (isset($extra['plugin']) ? [$extra['plugin']] : []))
                                        : ($extra['themes'] ?? (isset($extra['theme']) ? [$extra['theme']] : []));
            foreach ((array) $items as $item) {
                $names[] = (string) $item;
            }
        }

        $what = $type === 'plugin' ? 'プラグイン' : 'テーマ';
        $list = '📦 ' . implode(', ', array_map(static function ($n) {
            return '`' . Notifier::esc($n) . '`';
        }, $names));

        if ($action === 'install') {
            Notifier::send(Notifier::WARNING, "{$what}がインストールされました", [$list, Notifier::actorLine()]);
        } else {
            Notifier::send(Notifier::INFO, "{$what}が更新されました", [$list, Notifier::actorLine()]);
        }
    }

    /** @param \WP_Theme $newTheme @param \WP_Theme $oldTheme */
    public static function onSwitchTheme($newName, $newTheme = null, $oldTheme = null): void
    {
        $old = $oldTheme instanceof \WP_Theme ? $oldTheme->get('Name') : '?';
        Notifier::send(Notifier::WARNING, 'テーマが変更されました', [
            sprintf('🎨 `%s` → `%s`', Notifier::esc((string) $old), Notifier::esc((string) $newName)),
            Notifier::actorLine(),
        ]);
    }

    public static function onDeletedPlugin($file, $deleted): void
    {
        if ($deleted) {
            Notifier::send(Notifier::INFO, 'プラグインが削除されました', [self::pluginList([(string) $file]), Notifier::actorLine()]);
        }
    }

    /** @param string[] $files */
    private static function pluginList(array $files): string
    {
        $items = [];
        foreach ($files as $file) {
            $name = '';
            $path = WP_PLUGIN_DIR . '/' . $file;
            if (function_exists('get_file_data') && is_file($path)) {
                $data = get_file_data($path, ['Name' => 'Plugin Name']);
                $name = (string) $data['Name'];
            }
            $items[] = $name !== '' ? sprintf('%s (`%s`)', Notifier::esc($name), Notifier::esc($file)) : '`' . Notifier::esc($file) . '`';
        }
        return '🔌 ' . implode(', ', $items);
    }
}
