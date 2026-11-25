<?php

namespace WPGuard\Sentinel;

/**
 * P-02: reports new administrators.
 *
 * Hooks catch admins created through WordPress. A periodic comparison of the admin
 * list also catches admins inserted straight into the database, which hooks never see.
 */
final class UserMonitor
{
    private const ADMINS_OPTION = 'wpguard_known_admins';
    private const CHECK_INTERVAL = 300;

    /** @var array<int,array{created:bool,promoted:bool}> */
    private static $events = [];

    public static function register(): void
    {
        add_action('user_register', [self::class, 'onRegister'], 10, 1);
        add_action('set_user_role', [self::class, 'onSetRole'], 10, 3);
        add_action('add_user_role', [self::class, 'onAddRole'], 10, 2);
        add_action('grant_super_admin', [self::class, 'onPromote'], 10, 1);
        add_action('init', [self::class, 'periodicCheck'], 20);
        // Report after the request has finished changing users (role is set before user_register fires).
        add_action('shutdown', [self::class, 'report'], 100);
    }

    public static function onRegister($userId): void
    {
        self::$events[(int) $userId]['created'] = true;
    }

    public static function onSetRole($userId, $role, $oldRoles = []): void
    {
        if ($role === 'administrator' && !in_array('administrator', (array) $oldRoles, true)) {
            self::onPromote($userId);
        }
    }

    public static function onAddRole($userId, $role): void
    {
        if ($role === 'administrator') {
            self::onPromote($userId);
        }
    }

    public static function onPromote($userId): void
    {
        self::$events[(int) $userId]['promoted'] = true;
    }

    public static function report(): void
    {
        if (self::$events === []) {
            return;
        }
        $reported = false;
        foreach (self::$events as $id => $e) {
            $user = get_userdata($id);
            if (!$user || !self::isAdmin($user)) {
                continue;
            }
            $title = !empty($e['created']) ? '管理者アカウントが作成されました' : 'ユーザーが管理者に昇格しました';
            Notifier::send(Notifier::CRITICAL, $title, [
                self::userLine($user),
                Notifier::actorLine(),
                '心当たりがなければ、このアカウントを削除し、すべての管理者のパスワードを変更してください。',
            ]);
            $reported = true;
        }
        self::$events = [];
        if ($reported) {
            update_option(self::ADMINS_OPTION, self::adminIds(), false);
        }
    }

    public static function periodicCheck(): void
    {
        if (get_transient('wpguard_admin_check')) {
            return;
        }
        set_transient('wpguard_admin_check', 1, self::CHECK_INTERVAL);

        $current = self::adminIds();
        $known = get_option(self::ADMINS_OPTION, null);
        if (!is_array($known)) {
            update_option(self::ADMINS_OPTION, $current, false);
            return;
        }
        $known = array_map('intval', $known);
        $added = array_diff($current, $known);
        $removed = array_diff($known, $current);

        foreach ($added as $id) {
            if (isset(self::$events[$id])) {
                continue; // Reported by the hooks in this request.
            }
            $user = get_userdata($id);
            if ($user) {
                Notifier::send(Notifier::CRITICAL, '管理者が増えています (WordPress を通さずに追加された可能性)', [
                    self::userLine($user),
                    'データベースが直接書き換えられた可能性があります。心当たりがなければ、すぐに確認してください。',
                ]);
            }
        }
        if ($removed !== []) {
            Notifier::send(Notifier::WARNING, '管理者アカウントが削除または降格されました', [
                '🆔 ユーザー ID: ' . implode(', ', array_map('intval', $removed)),
            ]);
        }
        if ($added !== [] || $removed !== []) {
            update_option(self::ADMINS_OPTION, $current, false);
        }
    }

    /** @return int[] */
    private static function adminIds(): array
    {
        $ids = array_map('intval', get_users(['role' => 'administrator', 'fields' => 'ID', 'blog_id' => get_current_blog_id()]));
        if (is_multisite()) {
            foreach (get_super_admins() as $login) {
                $u = get_user_by('login', $login);
                if ($u) {
                    $ids[] = (int) $u->ID;
                }
            }
        }
        $ids = array_values(array_unique($ids));
        sort($ids);
        return $ids;
    }

    private static function isAdmin(\WP_User $user): bool
    {
        return in_array('administrator', (array) $user->roles, true) || (is_multisite() && is_super_admin($user->ID));
    }

    private static function userLine(\WP_User $user): string
    {
        return sprintf(
            '👤 ユーザー: `%s` (ID %d)  ✉️ `%s`',
            Notifier::esc($user->user_login),
            $user->ID,
            Notifier::esc($user->user_email)
        );
    }
}
