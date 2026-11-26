<?php

namespace WPGuard\Sentinel;

/**
 * P-07: two-factor authentication (TOTP) for administrators.
 *
 * Login: after the password is accepted, the login is stopped (auth cookie cleared) and the
 * user is sent to a second screen on wp-login.php to enter the 6-digit code. Only then is
 * the auth cookie set. Wrong codes count as failed logins (LoginGuard locks the IP).
 *
 * Rollout: administrators get WPGUARD_2FA_GRACE_DAYS days to set it up (a notice in the
 * admin screen). After that, an administrator without it must set it up on the login screen.
 *
 * Lost phone: 10 one-time recovery codes; as a last resort `wpguard 2fa-reset` on the server.
 */
final class TwoFactor
{
    public const META_SECRET = 'wpguard_2fa_secret';
    public const META_PENDING = 'wpguard_2fa_pending';
    public const META_LAST_STEP = 'wpguard_2fa_last_step';
    public const META_RECOVERY = 'wpguard_2fa_recovery';
    public const META_GRACE = 'wpguard_2fa_grace_start';

    private const ACTION = 'wpguard_2fa';
    private const PAGE = 'wpguard-2fa';
    private const TOKEN_TTL = 300;
    private const MAX_ATTEMPTS = 5;
    private const RECOVERY_COUNT = 10;
    private const RECOVERY_CHARS = 'abcdefghjkmnpqrstuvwxyz23456789';
    private const ISSUER_MAX = 40;

    /** @var Config */
    private static $config;
    /** @var bool set while we finish a login ourselves, so our own wp_login hook lets it through */
    private static $completing = false;

    public static function register(Config $config): void
    {
        self::$config = $config;
        if (!$config->twoFactor) {
            return;
        }
        add_action('wp_login', [self::class, 'interceptLogin'], 1, 2);
        add_action('login_form_' . self::ACTION, [self::class, 'loginScreen']);
        add_filter('login_message', [self::class, 'expiredMessage']);
        add_action('admin_menu', [self::class, 'adminMenu']);
        add_action('admin_notices', [self::class, 'adminNotice']);
        if (!$config->twoFactorAllowAppPasswords) {
            // Application passwords log in to the REST API without the second step;
            // an attacker with the password could create one and skip two-factor for good.
            add_filter('wp_is_application_passwords_available_for_user', [self::class, 'appPasswordsAvailable'], 10, 2);
        }
    }

    /** @param \WP_User $user */
    public static function appPasswordsAvailable($available, $user)
    {
        return $user instanceof \WP_User && (self::required($user) || self::enrolled($user)) ? false : $available;
    }

    // ------------------------------------------------------------------ who needs it

    public static function enrolled(\WP_User $user): bool
    {
        return (string) get_user_meta($user->ID, self::META_SECRET, true) !== '';
    }

    public static function required(\WP_User $user): bool
    {
        return array_intersect((array) $user->roles, self::$config->twoFactorRoles) !== []
            || (is_multisite() && is_super_admin($user->ID));
    }

    /** Seconds left in the grace period (starts at the user's first login after installation). */
    public static function graceLeft(\WP_User $user): int
    {
        $start = (int) get_user_meta($user->ID, self::META_GRACE, true);
        if ($start === 0) {
            $start = time();
            update_user_meta($user->ID, self::META_GRACE, $start);
        }
        return max(0, $start + self::$config->twoFactorGraceDays * DAY_IN_SECONDS - time());
    }

    // ------------------------------------------------------------------ login

    /** @param \WP_User $user */
    public static function interceptLogin($login, $user): void
    {
        if (self::$completing || !($user instanceof \WP_User)) {
            return;
        }
        $enrolled = self::enrolled($user);
        if (!$enrolled && (!self::required($user) || self::graceLeft($user) > 0)) {
            return;
        }

        // Undo the login that WordPress has just made; it is finished after the second step.
        wp_clear_auth_cookie();
        wp_set_current_user(0);

        $token = bin2hex(random_bytes(32));
        set_transient(self::tokenKey($token), [
            'user_id' => $user->ID,
            'remember' => !empty($_POST['rememberme']),
            'redirect_to' => isset($_REQUEST['redirect_to']) ? wp_unslash((string) $_REQUEST['redirect_to']) : '',
            'attempts' => 0,
            'enrolled_now' => false,
        ], self::TOKEN_TTL);

        wp_safe_redirect(add_query_arg(['action' => self::ACTION, 'wpguard_token' => $token], wp_login_url()));
        exit;
    }

    public static function loginScreen(): void
    {
        $token = isset($_REQUEST['wpguard_token']) ? preg_replace('/[^a-f0-9]/', '', (string) $_REQUEST['wpguard_token']) : '';
        $pending = $token !== '' ? get_transient(self::tokenKey($token)) : false;
        $user = is_array($pending) ? get_userdata((int) $pending['user_id']) : false;
        if (!is_array($pending) || !($user instanceof \WP_User)) {
            wp_safe_redirect(add_query_arg('wpguard_expired', '1', wp_login_url()));
            exit;
        }

        $error = '';
        if (LoginGuard::lockedFor(ClientIp::get()) > 0) {
            $error = 'ログインの失敗が続いたため、一時的にログインできません。しばらくしてからお試しください。';
        } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $step = isset($_POST['wpguard_step']) ? (string) $_POST['wpguard_step'] : '';
            $code = isset($_POST['wpguard_code']) ? trim(wp_unslash((string) $_POST['wpguard_code'])) : '';

            if ($step === 'finish' && !empty($pending['enrolled_now'])) {
                self::complete($token, $pending, $user);
            }
            if ($step === 'code' && self::enrolled($user)) {
                $how = self::check($user, $code);
                if ($how !== null) {
                    if ($how === 'recovery') {
                        self::noticeRecoveryUsed($user);
                    }
                    self::complete($token, $pending, $user);
                }
                $error = self::failed($token, $pending, $user);
            }
            if ($step === 'enroll' && !self::enrolled($user)) {
                if (self::finishEnrollment($user, $code)) {
                    $pending['enrolled_now'] = true;
                    set_transient(self::tokenKey($token), $pending, self::TOKEN_TTL);
                    self::render('二要素認証を設定しました', self::recoveryCodesHtml(self::issueRecoveryCodes($user))
                        . self::form($token, 'finish', '', 'ログインを続ける', false));
                }
                $error = self::failed($token, $pending, $user);
            }
        }

        if (self::enrolled($user)) {
            self::render('確認コードの入力', '<p>認証アプリに表示されている 6 桁のコードを入力してください。</p>'
                . '<p class="description">スマホが手元にないときは、予備コード (xxxx-xxxx) も使えます。</p>'
                . self::form($token, 'code', $error, 'ログイン'), $error);
        }
        self::render('二要素認証の設定', self::enrollHtml($user)
            . '<p><strong>この設定は必須です。</strong>設定が終わるとログインできます。</p>'
            . self::form($token, 'enroll', $error, '設定してログイン'), $error);
    }

    public static function expiredMessage($message)
    {
        if (isset($_GET['wpguard_expired'])) {
            $message .= '<p class="message">確認コードの入力時間が過ぎました。もう一度ログインしてください。</p>';
        }
        return $message;
    }

    /** @param array<string,mixed> $pending */
    private static function complete(string $token, array $pending, \WP_User $user): void
    {
        delete_transient(self::tokenKey($token));
        self::$completing = true;
        wp_set_auth_cookie($user->ID, (bool) $pending['remember'], is_ssl());
        wp_set_current_user($user->ID);
        do_action('wp_login', $user->user_login, $user);

        $requested = (string) $pending['redirect_to'];
        $to = $requested !== '' ? $requested : admin_url();
        $to = apply_filters('login_redirect', $to, $requested, $user);
        wp_safe_redirect($to !== '' ? $to : admin_url());
        exit;
    }

    /** @param array<string,mixed> $pending */
    private static function failed(string $token, array $pending, \WP_User $user): string
    {
        do_action('wp_login_failed', $user->user_login, new \WP_Error('wpguard_2fa_invalid', 'invalid code'));
        $pending['attempts'] = (int) $pending['attempts'] + 1;
        if ($pending['attempts'] >= self::MAX_ATTEMPTS) {
            delete_transient(self::tokenKey($token));
            wp_safe_redirect(add_query_arg('wpguard_expired', '1', wp_login_url()));
            exit;
        }
        set_transient(self::tokenKey($token), $pending, self::TOKEN_TTL);
        return 'コードが正しくありません。';
    }

    // ------------------------------------------------------------------ codes

    /** @return string|null 'totp' or 'recovery' when the code is accepted */
    public static function check(\WP_User $user, string $code): ?string
    {
        $secret = (string) get_user_meta($user->ID, self::META_SECRET, true);
        if ($secret === '') {
            return null;
        }
        $step = Totp::verify($secret, $code, (int) get_user_meta($user->ID, self::META_LAST_STEP, true));
        if ($step !== null) {
            update_user_meta($user->ID, self::META_LAST_STEP, $step);
            return 'totp';
        }
        $normalized = strtolower(preg_replace('/[^a-z0-9]/i', '', $code) ?? '');
        if (strlen($normalized) !== 8) {
            return null;
        }
        $hashes = (array) get_user_meta($user->ID, self::META_RECOVERY, true);
        foreach ($hashes as $i => $hash) {
            if (is_string($hash) && wp_check_password($normalized, $hash)) {
                unset($hashes[$i]);
                update_user_meta($user->ID, self::META_RECOVERY, array_values($hashes));
                return 'recovery';
            }
        }
        return null;
    }

    /** @return string[] the new codes, shown once */
    public static function issueRecoveryCodes(\WP_User $user): array
    {
        $codes = [];
        $hashes = [];
        $max = strlen(self::RECOVERY_CHARS) - 1;
        for ($i = 0; $i < self::RECOVERY_COUNT; $i++) {
            $c = '';
            for ($j = 0; $j < 8; $j++) {
                $c .= self::RECOVERY_CHARS[random_int(0, $max)];
            }
            $codes[] = substr($c, 0, 4) . '-' . substr($c, 4);
            $hashes[] = wp_hash_password($c);
        }
        update_user_meta($user->ID, self::META_RECOVERY, $hashes);
        return $codes;
    }

    public static function pendingSecret(\WP_User $user): string
    {
        $secret = (string) get_user_meta($user->ID, self::META_PENDING, true);
        if ($secret === '') {
            $secret = Totp::newSecret();
            update_user_meta($user->ID, self::META_PENDING, $secret);
        }
        return $secret;
    }

    public static function finishEnrollment(\WP_User $user, string $code): bool
    {
        $secret = self::pendingSecret($user);
        $step = Totp::verify($secret, $code, 0);
        if ($step === null) {
            return false;
        }
        update_user_meta($user->ID, self::META_SECRET, $secret);
        update_user_meta($user->ID, self::META_LAST_STEP, $step);
        delete_user_meta($user->ID, self::META_PENDING);
        Notifier::send(Notifier::INFO, '二要素認証が設定されました', ['👤 ユーザー: `' . Notifier::esc($user->user_login) . '`']);
        return true;
    }

    private static function noticeRecoveryUsed(\WP_User $user): void
    {
        $left = count((array) get_user_meta($user->ID, self::META_RECOVERY, true));
        Notifier::send(Notifier::WARNING, '予備コードでログインしました', [
            sprintf('👤 ユーザー: `%s`  🌐 IP: `%s`  🔑 残りの予備コード: %d 個', Notifier::esc($user->user_login), Notifier::esc(ClientIp::get()), $left),
            'スマホをなくした場合は、認証アプリを設定し直してください。心当たりがなければ、パスワードを変更してください。',
        ]);
    }

    // ------------------------------------------------------------------ admin screen

    public static function adminMenu(): void
    {
        // Under "Users" for administrators, under "Profile" for everyone else.
        add_users_page('二要素認証', '二要素認証', 'read', self::PAGE, [self::class, 'adminPage']);
    }

    public static function pageUrl(): string
    {
        return admin_url((current_user_can('edit_users') ? 'users.php' : 'profile.php') . '?page=' . self::PAGE);
    }

    public static function adminPage(): void
    {
        $user = wp_get_current_user();
        echo '<div class="wrap"><h1>二要素認証</h1>';

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && check_admin_referer('wpguard_2fa_' . $user->ID)) {
            $action = isset($_POST['wpguard_action']) ? (string) $_POST['wpguard_action'] : '';
            if ($action === 'enroll' && !self::enrolled($user)) {
                $code = isset($_POST['wpguard_code']) ? wp_unslash((string) $_POST['wpguard_code']) : '';
                if (self::finishEnrollment($user, $code)) {
                    echo '<div class="notice notice-success"><p>二要素認証を設定しました。次回のログインから、確認コードが必要になります。</p></div>';
                    echo self::recoveryCodesHtml(self::issueRecoveryCodes($user)) . '</div>';
                    return;
                }
                echo '<div class="notice notice-error"><p>コードが正しくありません。アプリに表示されている最新のコードを入力してください。</p></div>';
            } elseif ($action === 'regenerate' && self::enrolled($user)) {
                echo '<div class="notice notice-success"><p>予備コードを作り直しました。前の予備コードは使えなくなりました。</p></div>';
                echo self::recoveryCodesHtml(self::issueRecoveryCodes($user)) . '</div>';
                return;
            } elseif ($action === 'disable' && self::enrolled($user) && !self::required($user)) {
                foreach ([self::META_SECRET, self::META_LAST_STEP, self::META_RECOVERY] as $k) {
                    delete_user_meta($user->ID, $k);
                }
                echo '<div class="notice notice-success"><p>二要素認証を解除しました。</p></div>';
            }
        }

        if (self::enrolled($user)) {
            $left = count((array) get_user_meta($user->ID, self::META_RECOVERY, true));
            echo '<p>✅ <strong>二要素認証は有効です。</strong>ログインのたびに、認証アプリの確認コードが必要です。</p>';
            printf('<p>残りの予備コード: <strong>%d 個</strong>%s</p>', $left, $left <= 3 ? ' (少なくなっています。作り直してください)' : '');
            echo self::adminForm($user, 'regenerate', '予備コードを作り直す', 'button');
            if (!self::required($user)) {
                echo self::adminForm($user, 'disable', '二要素認証を解除する', 'button button-link-delete');
            } else {
                echo '<p class="description">管理者は二要素認証が必須のため、解除できません。スマホをなくして予備コードもない場合は、サーバーの管理者に解除を依頼してください。</p>';
            }
        } else {
            echo self::enrollHtml($user);
            echo '<form method="post">';
            wp_nonce_field('wpguard_2fa_' . $user->ID);
            echo '<input type="hidden" name="wpguard_action" value="enroll">';
            echo '<p><label for="wpguard_code"><strong>3. アプリに表示された 6 桁のコード</strong></label><br>';
            echo '<input type="text" id="wpguard_code" name="wpguard_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="7" class="regular-text" style="font-size:1.4em;letter-spacing:.2em;width:9em" required></p>';
            submit_button('設定する');
            echo '</form>';
        }
        echo '</div>';
    }

    public static function adminNotice(): void
    {
        $user = wp_get_current_user();
        if (!$user->exists() || self::enrolled($user) || !self::required($user)) {
            return;
        }
        if (isset($_GET['page']) && $_GET['page'] === self::PAGE) {
            return;
        }
        $days = (int) ceil(self::graceLeft($user) / DAY_IN_SECONDS);
        printf(
            '<div class="notice notice-warning"><p><strong>二要素認証の設定が必要です。</strong>あと %d 日で、設定しないとログインできなくなります (ログイン画面で設定すれば入れます)。 <a href="%s" class="button button-primary">今すぐ設定する</a></p></div>',
            $days,
            esc_url(self::pageUrl())
        );
    }

    // ------------------------------------------------------------------ html

    private static function enrollHtml(\WP_User $user): string
    {
        $secret = self::pendingSecret($user);
        $issuer = mb_strimwidth(wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES) ?: (string) wp_parse_url(home_url(), PHP_URL_HOST), 0, self::ISSUER_MAX, '', 'UTF-8');
        $uri = Totp::uri($secret, $user->user_login, $issuer);
        return '<p><strong>1. スマホに認証アプリを入れます。</strong><br>Google Authenticator、Microsoft Authenticator、1Password など、どれでもかまいません。</p>'
            . '<p><strong>2. アプリでアカウントを追加し、次の設定キーを入力します。</strong></p>'
            . '<p><code style="font-size:1.3em;letter-spacing:.08em;padding:.4em .6em;display:inline-block;user-select:all">' . esc_html(Totp::grouped($secret)) . '</code></p>'
            . '<p class="description">アカウント名: ' . esc_html($user->user_login) . ' / 種類: 時間ベース<br>'
            . 'このページをスマホで開いている場合は、<a href="' . esc_attr($uri) . '">ここをタップ</a>するとアプリに追加できます。</p>';
    }

    /** @param string[] $codes */
    private static function recoveryCodesHtml(array $codes): string
    {
        return '<h2>予備コード</h2>'
            . '<p><strong>スマホをなくしたときに、確認コードの代わりに使えます。</strong>それぞれ 1 回だけ使えます。<br>'
            . 'この画面を閉じると二度と表示されません。パスワード管理アプリなど、安全な場所に保存してください。</p>'
            . '<pre style="font-size:1.2em;line-height:1.7;background:#f6f7f7;padding:1em 1.5em;display:inline-block;user-select:all">'
            . esc_html(implode("\n", $codes)) . '</pre>';
    }

    private static function form(string $token, string $step, string $error, string $button, bool $withInput = true): string
    {
        $html = '<form method="post" action="' . esc_url(add_query_arg(['action' => self::ACTION], wp_login_url())) . '">'
            . '<input type="hidden" name="wpguard_token" value="' . esc_attr($token) . '">'
            . '<input type="hidden" name="wpguard_step" value="' . esc_attr($step) . '">';
        if ($withInput) {
            $html .= '<p><label for="wpguard_code">確認コード</label>'
                . '<input type="text" name="wpguard_code" id="wpguard_code" class="input" inputmode="numeric" autocomplete="one-time-code" autofocus required style="font-size:1.6em;letter-spacing:.2em;text-align:center"></p>';
        }
        return $html . '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr($button) . '"></p></form>';
    }

    private static function adminForm(\WP_User $user, string $action, string $label, string $class): string
    {
        ob_start();
        echo '<form method="post" style="display:inline-block;margin-right:1em">';
        wp_nonce_field('wpguard_2fa_' . $user->ID);
        echo '<input type="hidden" name="wpguard_action" value="' . esc_attr($action) . '">';
        echo '<button type="submit" class="' . esc_attr($class) . '">' . esc_html($label) . '</button></form>';
        return (string) ob_get_clean();
    }

    private static function render(string $title, string $body, string $error = ''): void
    {
        nocache_headers();
        header('X-Frame-Options: DENY');
        $errors = new \WP_Error();
        if ($error !== '') {
            $errors->add('wpguard_2fa', $error);
        }
        if (function_exists('login_header')) {
            login_header($title, '', $errors);
            echo '<div style="background:#fff;padding:1.5em 1.5em .5em;box-shadow:0 1px 3px rgba(0,0,0,.13)">' . $body . '</div>';
            login_footer();
        } else {
            echo '<!doctype html><meta charset="utf-8"><title>' . esc_html($title) . '</title>' . $body;
        }
        exit;
    }

    private static function tokenKey(string $token): string
    {
        return 'wpguard_2fa_' . hash('sha256', $token);
    }
}
