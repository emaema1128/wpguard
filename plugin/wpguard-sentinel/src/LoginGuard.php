<?php

namespace WPGuard\Sentinel;

/**
 * P-01: limits login attempts per IP address.
 *
 * Locking is per IP, not per user name: locking a user name would let anyone
 * lock the real administrator out by typing their name wrong a few times.
 */
final class LoginGuard
{
    private const NOTICE_LIMIT_PER_HOUR = 5;
    private const KNOWN_IPS_META = 'wpguard_known_ips';
    private const KNOWN_IPS_MAX = 20;
    private const PROBE_CODES = ['invalid_username', 'invalid_email', 'incorrect_password'];

    /** @var Config */
    private static $config;

    public static function register(Config $config): void
    {
        self::$config = $config;
        ClientIp::configure($config->trustedProxies);

        // Priority 99: after WordPress has checked the password, so a correct password
        // does not get through while the IP is locked.
        add_filter('authenticate', [self::class, 'enforce'], 99, 3);
        add_action('wp_login_failed', [self::class, 'failed'], 10, 2);
        add_action('wp_login', [self::class, 'succeeded'], 10, 2);
    }

    /**
     * @param \WP_User|\WP_Error|null $user
     * @return \WP_User|\WP_Error|null
     */
    public static function enforce($user, $username = '', $password = '')
    {
        if ($username === '' || $username === null) {
            return $user;
        }
        $remaining = self::lockedFor(ClientIp::get());
        if ($remaining > 0) {
            return new \WP_Error('wpguard_locked', self::lockMessage($remaining));
        }
        // Same message for "no such user" and "wrong password", so user names and e-mail addresses cannot be probed.
        if ($user instanceof \WP_Error && array_intersect($user->get_error_codes(), self::PROBE_CODES) !== []) {
            return new \WP_Error('wpguard_invalid_login', '<strong>エラー</strong>: ユーザー名またはパスワードが正しくありません。');
        }
        return $user;
    }

    /** @param \WP_Error|null $error */
    public static function failed($username, $error = null): void
    {
        if ($error instanceof \WP_Error && $error->get_error_code() === 'wpguard_locked') {
            return;
        }
        $ip = ClientIp::get();
        $key = self::key('fail', $ip);
        $state = get_transient($key);
        if (!is_array($state)) {
            $state = ['count' => 0, 'users' => []];
        }
        $state['count']++;
        $name = substr((string) $username, 0, 60);
        if ($name !== '' && !in_array($name, $state['users'], true) && count($state['users']) < 5) {
            $state['users'][] = $name;
        }

        if ($state['count'] < self::$config->loginMaxRetries) {
            set_transient($key, $state, self::$config->loginWindow);
            return;
        }

        delete_transient($key);
        set_transient(self::key('lock', $ip), time() + self::$config->loginLockout, self::$config->loginLockout);
        AuditLog::record('login.locked', $ip, ['failures' => $state['count'], 'users' => implode(', ', $state['users']), 'minutes' => (int) (self::$config->loginLockout / 60)]);
        self::noticeLock($ip, $state);
    }

    /** @param \WP_User $user */
    public static function succeeded($login, $user): void
    {
        $ip = ClientIp::get();
        delete_transient(self::key('fail', $ip));
        if (!($user instanceof \WP_User) || !user_can($user, 'manage_options')) {
            return;
        }

        $known = get_user_meta($user->ID, self::KNOWN_IPS_META, true);
        $known = is_array($known) ? $known : [];
        if (in_array($ip, $known, true)) {
            return;
        }
        // The first login after installing this plugin just records the address.
        if ($known !== []) {
            Notifier::send(Notifier::WARNING, '管理者が新しい IP アドレスからログインしました', [
                sprintf('👤 ユーザー: %s  🌐 IP: `%s`', Notifier::esc($user->user_login), Notifier::esc($ip)),
                '心当たりがなければ、パスワードを変更し、ほかのセッションをログアウトさせてください。',
            ]);
        }
        $known[] = $ip;
        update_user_meta($user->ID, self::KNOWN_IPS_META, array_slice($known, -self::KNOWN_IPS_MAX));
    }

    public static function lockedFor(string $ip): int
    {
        $until = get_transient(self::key('lock', $ip));
        return is_numeric($until) ? max(0, (int) $until - time()) : 0;
    }

    private static function lockMessage(int $seconds): string
    {
        return sprintf(
            '<strong>エラー</strong>: ログインの失敗が続いたため、一時的にログインできません。約 %d 分後にもう一度お試しください。',
            (int) ceil($seconds / 60)
        );
    }

    /** @param array{count:int,users:string[]} $state */
    private static function noticeLock(string $ip, array $state): void
    {
        // A distributed attack can lock hundreds of IPs; do not flood Slack.
        $sent = (int) get_transient('wpguard_lock_notices');
        set_transient('wpguard_lock_notices', $sent + 1, HOUR_IN_SECONDS);
        if ($sent > self::NOTICE_LIMIT_PER_HOUR) {
            return;
        }
        if ($sent === self::NOTICE_LIMIT_PER_HOUR) {
            Notifier::send(Notifier::WARNING, 'ログイン攻撃が続いています', [
                '1 時間に多数の IP アドレスをロックしました。これ以上のロック通知は 1 時間止めます (ロック自体は続けます)。',
            ]);
            return;
        }
        $users = array_map(static function ($u) {
            return '`' . Notifier::esc($u) . '`';
        }, $state['users']);
        Notifier::send(Notifier::WARNING, 'ログインの失敗が続いたため、IP アドレスをロックしました', [
            sprintf('🌐 IP: `%s`  (%d 回失敗、%d 分間ロック)', Notifier::esc($ip), $state['count'], (int) (self::$config->loginLockout / 60)),
            '🔑 試されたユーザー名: ' . ($users === [] ? '(なし)' : implode(', ', $users)),
        ]);
    }

    private static function key(string $kind, string $ip): string
    {
        return 'wpguard_' . $kind . '_' . md5($ip);
    }
}
