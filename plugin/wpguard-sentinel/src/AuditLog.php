<?php

namespace WPGuard\Sentinel;

/**
 * P-11: who did what, when, from where.
 *
 * Kept in a table of the site's database (viewable under Tools → 操作ログ) and also written
 * to the server's syslog. An attacker with administrator rights can empty the table, but
 * cannot touch syslog, which belongs to root.
 */
final class AuditLog
{
    private const DB_VERSION = '1';
    private const DB_VERSION_OPTION = 'wpguard_audit_db_version';
    private const PAGE = 'wpguard-audit';
    private const PER_PAGE = 50;
    private const MAX_ROWS = 200000;

    /** Settings worth an entry when they change (an attacker opening registration as admin, ...). */
    private const WATCHED_OPTIONS = [
        'siteurl' => 'サイトアドレス (siteurl)',
        'home' => 'サイトアドレス (home)',
        'admin_email' => '管理者メールアドレス',
        'users_can_register' => 'だれでもユーザー登録ができる',
        'default_role' => '新規ユーザーの権限グループ',
        'blogname' => 'サイトのタイトル',
        'permalink_structure' => 'パーマリンク構造',
    ];

    public const LABELS = [
        'login.success' => 'ログイン',
        'login.failed' => 'ログイン失敗',
        'login.locked' => 'IP をロック',
        'logout' => 'ログアウト',
        '2fa.enrolled' => '二要素認証を設定',
        '2fa.recovery_used' => '予備コードを使用',
        'user.created' => 'ユーザー作成',
        'user.role_changed' => '権限グループの変更',
        'user.deleted' => 'ユーザー削除',
        'user.password_changed' => 'パスワード変更',
        'user.email_changed' => 'メールアドレス変更',
        'plugin.activated' => 'プラグイン有効化',
        'plugin.deactivated' => 'プラグイン無効化',
        'plugin.installed' => 'プラグインのインストール',
        'plugin.updated' => 'プラグインの更新',
        'plugin.deleted' => 'プラグイン削除',
        'theme.switched' => 'テーマの変更',
        'theme.installed' => 'テーマのインストール',
        'theme.updated' => 'テーマの更新',
        'core.updated' => 'WordPress の更新',
        'option.changed' => '設定の変更',
        'post.published' => '公開',
        'post.trashed' => 'ゴミ箱へ移動',
        'post.deleted' => '完全に削除',
        'media.uploaded' => 'ファイルのアップロード',
    ];

    private const GROUPS = [
        'login' => 'ログイン', '2fa' => '二要素認証', 'user' => 'ユーザー', 'plugin' => 'プラグイン',
        'theme' => 'テーマ', 'core' => 'WordPress 本体', 'option' => '設定', 'post' => '投稿・ページ', 'media' => 'メディア',
    ];

    /** @var Config */
    private static $config;
    /** @var bool */
    private static $tableReady = false;

    public static function register(Config $config): void
    {
        self::$config = $config;
        if (!$config->auditLog) {
            return;
        }
        add_action('wp_login', [self::class, 'onLogin'], 20, 2);
        add_action('wp_login_failed', [self::class, 'onLoginFailed'], 20, 2);
        add_action('wp_logout', [self::class, 'onLogout'], 10, 1);

        add_action('user_register', [self::class, 'onUserRegister'], 20, 1);
        add_action('set_user_role', [self::class, 'onSetRole'], 20, 3);
        add_action('delete_user', [self::class, 'onDeleteUser'], 10, 1);
        add_action('profile_update', [self::class, 'onProfileUpdate'], 10, 2);
        add_action('after_password_reset', [self::class, 'onPasswordReset'], 10, 1);

        add_action('activated_plugin', [self::class, 'onActivated'], 10, 1);
        add_action('deactivated_plugin', [self::class, 'onDeactivated'], 10, 1);
        add_action('deleted_plugin', [self::class, 'onDeletedPlugin'], 10, 2);
        add_action('upgrader_process_complete', [self::class, 'onUpgrade'], 20, 2);
        add_action('switch_theme', [self::class, 'onSwitchTheme'], 20, 1);

        foreach (array_keys(self::WATCHED_OPTIONS) as $option) {
            add_action("update_option_{$option}", [self::class, 'onOptionChanged'], 10, 3);
        }

        add_action('transition_post_status', [self::class, 'onPostStatus'], 10, 3);
        add_action('before_delete_post', [self::class, 'onDeletePost'], 10, 1);
        add_action('add_attachment', [self::class, 'onAttachment'], 10, 1);

        add_action('admin_menu', [self::class, 'adminMenu']);
        add_action('init', [self::class, 'maybePurge'], 40);
    }

    // ------------------------------------------------------------------ recording

    /**
     * @param array<string,mixed> $details
     * @param \WP_User|null $user who did it (default: the current user)
     */
    public static function record(string $event, string $object = '', array $details = [], $user = null): void
    {
        if (self::$config === null || !self::$config->auditLog) {
            return;
        }
        if (!($user instanceof \WP_User)) {
            $current = wp_get_current_user();
            $user = $current->exists() ? $current : null;
        }
        $login = $user ? $user->user_login : (defined('WP_CLI') && WP_CLI ? 'WP-CLI' : (wp_doing_cron() ? 'WP-Cron' : ''));
        if (isset($details['_login'])) {
            $login = (string) $details['_login'];
            unset($details['_login']);
        }
        $ip = ClientIp::get();
        $object = mb_substr($object, 0, 250, 'UTF-8');

        if (self::$config->auditSyslog && function_exists('syslog')) {
            self::syslog($event, $login, $ip, $object, $details);
        }
        if (self::$config->auditFile !== '') {
            @file_put_contents(self::$config->auditFile, self::line($event, $login, $ip, $object, $details) . "\n", FILE_APPEND | LOCK_EX);
        }

        global $wpdb;
        if (!self::ensureTable()) {
            return;
        }
        $wpdb->insert(self::table(), [
            'created' => gmdate('Y-m-d H:i:s'),
            'user_id' => $user ? (int) $user->ID : 0,
            'user_login' => mb_substr($login, 0, 60, 'UTF-8'),
            'ip' => $ip,
            'event' => $event,
            'object' => $object,
            'details' => $details === [] ? null : wp_json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
    }

    /** One line, e.g.: site=example.com event=login.failed user="admin" ip=203.0.113.10 object="" details={...} */
    public static function line(string $event, string $login, string $ip, string $object, array $details): string
    {
        $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
        $q = static function (string $s): string {
            return '"' . str_replace(['\\', '"', "\r", "\n"], ['\\\\', '\\"', ' ', ' '], $s) . '"';
        };
        $line = sprintf('site=%s event=%s user=%s ip=%s object=%s', $host, $event, $q($login), $ip, $q($object));
        if ($details !== []) {
            $line .= ' details=' . str_replace(["\r", "\n"], ' ', (string) wp_json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        }
        return $line;
    }

    private static function syslog(string $event, string $login, string $ip, string $object, array $details): void
    {
        // Our own connection, closed right away, so other code using syslog keeps its settings.
        openlog('wpguard', LOG_ODELAY, LOG_USER);
        $level = in_array($event, ['login.failed', 'login.locked'], true) ? LOG_WARNING : LOG_NOTICE;
        syslog($level, self::line($event, $login, $ip, $object, $details));
        closelog();
    }

    public static function table(): string
    {
        global $wpdb;
        return $wpdb->prefix . 'wpguard_log';
    }

    private static function ensureTable(): bool
    {
        if (self::$tableReady || get_option(self::DB_VERSION_OPTION) === self::DB_VERSION) {
            return self::$tableReady = true;
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = self::table();
        dbDelta("CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            created datetime NOT NULL,
            user_id bigint(20) unsigned NOT NULL DEFAULT 0,
            user_login varchar(60) NOT NULL DEFAULT '',
            ip varchar(45) NOT NULL DEFAULT '',
            event varchar(40) NOT NULL,
            object varchar(255) NOT NULL DEFAULT '',
            details text,
            PRIMARY KEY  (id),
            KEY event (event),
            KEY created (created)
        ) {$wpdb->get_charset_collate()};");
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) !== $table) {
            return false;
        }
        update_option(self::DB_VERSION_OPTION, self::DB_VERSION, true);
        return self::$tableReady = true;
    }

    public static function maybePurge(): void
    {
        if (get_transient('wpguard_audit_purge') || get_option(self::DB_VERSION_OPTION) !== self::DB_VERSION) {
            return;
        }
        set_transient('wpguard_audit_purge', 1, DAY_IN_SECONDS);
        global $wpdb;
        $table = self::table();
        $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE created < %s", gmdate('Y-m-d H:i:s', time() - self::$config->auditDays * DAY_IN_SECONDS)));
        $max = (int) $wpdb->get_var("SELECT MAX(id) FROM {$table}");
        if ($max > self::MAX_ROWS) {
            $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE id <= %d", $max - self::MAX_ROWS));
        }
    }

    // ------------------------------------------------------------------ hooks

    public static function onLogin($login, $user): void
    {
        self::record('login.success', '', [], $user instanceof \WP_User ? $user : null);
    }

    public static function onLoginFailed($username, $error = null): void
    {
        $code = $error instanceof \WP_Error ? $error->get_error_code() : '';
        if ($code === 'wpguard_locked') {
            return; // rejected while locked; the lock itself is recorded
        }
        $details = ['_login' => (string) $username];
        if ($code === 'wpguard_2fa_invalid') {
            $details['reason'] = '確認コードの間違い';
        }
        self::record('login.failed', '', $details);
    }

    public static function onLogout($userId = 0): void
    {
        $user = $userId ? get_userdata((int) $userId) : null;
        self::record('logout', '', [], $user ?: null);
    }

    public static function onUserRegister($userId): void
    {
        $u = get_userdata((int) $userId);
        if ($u) {
            self::record('user.created', $u->user_login, ['role' => implode(',', (array) $u->roles), 'email' => $u->user_email]);
        }
    }

    public static function onSetRole($userId, $role, $oldRoles = []): void
    {
        $old = implode(',', (array) $oldRoles);
        if ($old === '' || $old === $role) {
            return; // the role given at creation is part of user.created
        }
        $u = get_userdata((int) $userId);
        self::record('user.role_changed', $u ? $u->user_login : "#{$userId}", ['from' => $old, 'to' => (string) $role]);
    }

    public static function onDeleteUser($userId): void
    {
        $u = get_userdata((int) $userId);
        self::record('user.deleted', $u ? $u->user_login : "#{$userId}", $u ? ['role' => implode(',', (array) $u->roles)] : []);
    }

    /** @param \WP_User $old */
    public static function onProfileUpdate($userId, $old): void
    {
        $new = get_userdata((int) $userId);
        if (!$new || !($old instanceof \WP_User)) {
            return;
        }
        if ($old->user_pass !== $new->user_pass) {
            self::record('user.password_changed', $new->user_login);
        }
        if ($old->user_email !== $new->user_email) {
            self::record('user.email_changed', $new->user_login, ['from' => $old->user_email, 'to' => $new->user_email]);
        }
    }

    /** @param \WP_User $user */
    public static function onPasswordReset($user): void
    {
        if ($user instanceof \WP_User) {
            self::record('user.password_changed', $user->user_login, ['via' => 'パスワードリセット']);
        }
    }

    public static function onActivated($plugin): void
    {
        self::record('plugin.activated', (string) $plugin);
    }

    public static function onDeactivated($plugin): void
    {
        self::record('plugin.deactivated', (string) $plugin);
    }

    public static function onDeletedPlugin($plugin, $deleted): void
    {
        if ($deleted) {
            self::record('plugin.deleted', (string) $plugin);
        }
    }

    public static function onUpgrade($upgrader, $extra): void
    {
        $type = isset($extra['type']) ? (string) $extra['type'] : '';
        $action = isset($extra['action']) ? (string) $extra['action'] : '';
        if ($type === 'core') {
            self::record('core.updated', get_bloginfo('version'));
            return;
        }
        if (!in_array($type, ['plugin', 'theme'], true) || !in_array($action, ['install', 'update'], true)) {
            return;
        }
        if ($action === 'install') {
            $data = $type === 'plugin' ? ($upgrader->new_plugin_data ?? []) : ($upgrader->new_theme_data ?? []);
            $name = is_array($data) && !empty($data['Name']) ? (string) $data['Name']
                : (is_array($upgrader->result ?? null) ? (string) ($upgrader->result['destination_name'] ?? '') : '');
            self::record("{$type}.installed", $name);
            return;
        }
        $items = $type === 'plugin' ? ($extra['plugins'] ?? (isset($extra['plugin']) ? [$extra['plugin']] : []))
                                    : ($extra['themes'] ?? (isset($extra['theme']) ? [$extra['theme']] : []));
        foreach ((array) $items as $item) {
            self::record("{$type}.updated", (string) $item);
        }
    }

    public static function onSwitchTheme($name): void
    {
        self::record('theme.switched', (string) $name);
    }

    public static function onOptionChanged($old, $new, $option): void
    {
        $show = static function ($v): string {
            return is_scalar($v) ? mb_strimwidth((string) $v, 0, 100, '…', 'UTF-8') : '(複雑な値)';
        };
        self::record('option.changed', self::WATCHED_OPTIONS[$option] ?? (string) $option, ['from' => $show($old), 'to' => $show($new)]);
    }

    /** @param \WP_Post $post */
    public static function onPostStatus($new, $old, $post): void
    {
        if (!($post instanceof \WP_Post) || !in_array($post->post_type, ['post', 'page'], true) || $new === $old) {
            return;
        }
        if ($new === 'publish') {
            self::record('post.published', self::postLabel($post));
        } elseif ($new === 'trash') {
            self::record('post.trashed', self::postLabel($post));
        }
    }

    public static function onDeletePost($postId): void
    {
        $post = get_post((int) $postId);
        if ($post instanceof \WP_Post && in_array($post->post_type, ['post', 'page'], true)) {
            self::record('post.deleted', self::postLabel($post));
        }
    }

    public static function onAttachment($postId): void
    {
        $file = get_attached_file((int) $postId);
        self::record('media.uploaded', $file ? basename($file) : "#{$postId}", ['mime' => (string) get_post_mime_type((int) $postId)]);
    }

    private static function postLabel(\WP_Post $post): string
    {
        return sprintf('%s #%d「%s」', $post->post_type === 'page' ? '固定ページ' : '投稿', $post->ID, mb_strimwidth($post->post_title, 0, 60, '…', 'UTF-8'));
    }

    // ------------------------------------------------------------------ admin screen

    public static function adminMenu(): void
    {
        add_management_page('操作ログ', '操作ログ', 'manage_options', self::PAGE, [self::class, 'adminPage']);
    }

    public static function adminPage(): void
    {
        global $wpdb;
        echo '<div class="wrap"><h1>操作ログ</h1>';
        if (!self::ensureTable()) {
            echo '<p>ログの保存先 (データベースのテーブル) を作成できませんでした。</p></div>';
            return;
        }
        $group = isset($_GET['group']) ? sanitize_key((string) $_GET['group']) : '';
        $who = isset($_GET['who']) ? sanitize_text_field(wp_unslash((string) $_GET['who'])) : '';
        $paged = max(1, isset($_GET['paged']) ? (int) $_GET['paged'] : 1);

        $where = ['1=1'];
        $args = [];
        if (isset(self::GROUPS[$group])) {
            $where[] = 'event LIKE %s';
            $args[] = $wpdb->esc_like($group) . '%';
        }
        if ($who !== '') {
            $where[] = '(user_login LIKE %s OR ip LIKE %s OR object LIKE %s)';
            $like = '%' . $wpdb->esc_like($who) . '%';
            array_push($args, $like, $like, $like);
        }
        $table = self::table();
        $sqlWhere = implode(' AND ', $where);
        $total = (int) ($args === [] ? $wpdb->get_var("SELECT COUNT(*) FROM {$table}") : $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE {$sqlWhere}", $args)));
        $offset = ($paged - 1) * self::PER_PAGE;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} WHERE {$sqlWhere} ORDER BY id DESC LIMIT %d OFFSET %d",
            array_merge($args, [self::PER_PAGE, $offset])
        ));

        echo '<form method="get" style="margin:1em 0"><input type="hidden" name="page" value="' . esc_attr(self::PAGE) . '">';
        echo '<select name="group"><option value="">すべての種類</option>';
        foreach (self::GROUPS as $k => $label) {
            printf('<option value="%s"%s>%s</option>', esc_attr($k), selected($group, $k, false), esc_html($label));
        }
        echo '</select> <input type="search" name="who" value="' . esc_attr($who) . '" placeholder="ユーザー名・IP・対象" style="width:16em"> ';
        echo '<button type="submit" class="button">絞り込む</button>';
        printf(' <span class="description">%s 件 / 保存期間 %d 日 / サーバーのシステムログ (syslog) にも記録%s</span>', number_format_i18n($total), self::$config->auditDays, self::$config->auditSyslog ? 'しています' : 'していません');
        echo '</form>';

        echo '<table class="widefat striped"><thead><tr><th style="width:11em">日時</th><th>操作</th><th>対象</th><th>ユーザー</th><th>IP</th><th>詳細</th></tr></thead><tbody>';
        if (!$rows) {
            echo '<tr><td colspan="6">記録はありません。</td></tr>';
        }
        foreach ((array) $rows as $r) {
            $details = $r->details ? json_decode((string) $r->details, true) : [];
            $text = [];
            foreach ((array) $details as $k => $v) {
                $text[] = $k === 'from' ? '変更前: ' . $v : ($k === 'to' ? '変更後: ' . $v : $k . ': ' . (is_scalar($v) ? $v : wp_json_encode($v)));
            }
            $warn = in_array($r->event, ['login.failed', 'login.locked', 'user.role_changed', 'plugin.installed', 'option.changed', '2fa.recovery_used'], true);
            printf(
                '<tr><td>%s</td><td>%s%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>',
                esc_html(Notifier::date('Y-m-d H:i:s', strtotime($r->created . ' UTC'))),
                $warn ? '⚠️ ' : '',
                esc_html(self::LABELS[$r->event] ?? $r->event),
                esc_html($r->object),
                esc_html($r->user_login !== '' ? $r->user_login : '—'),
                esc_html($r->ip),
                esc_html(implode(' / ', $text))
            );
        }
        echo '</tbody></table>';

        $pages = (int) ceil($total / self::PER_PAGE);
        if ($pages > 1) {
            echo '<div class="tablenav"><div class="tablenav-pages">' . paginate_links([
                'base' => add_query_arg('paged', '%#%'),
                'format' => '',
                'current' => $paged,
                'total' => $pages,
            ]) . '</div></div>';
        }
        echo '</div>';
    }
}
