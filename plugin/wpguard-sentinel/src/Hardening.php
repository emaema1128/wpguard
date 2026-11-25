<?php

namespace WPGuard\Sentinel;

/**
 * P-04: no file editing from the admin screen.
 * P-05: no XML-RPC, no user name enumeration.
 * P-06: no PHP execution in uploads (.htaccess, recreated if removed).
 */
final class Hardening
{
    private const HTACCESS_MARKER = 'WPGuard';
    private const HTACCESS_OPTION = 'wpguard_uploads_htaccess';
    private const HTACCESS_CHECK_INTERVAL = 3600;

    private const HTACCESS_RULES = [
        '# uploads 内では PHP を実行しない',
        '<FilesMatch "\.(?i:php[0-9]?|phtml|pht|phar|phps|inc)$">',
        '    Require all denied',
        '</FilesMatch>',
    ];

    public static function register(Config $config): void
    {
        if (!$config->allowFileEdit) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
            // Also covers sites where wp-config.php sets DISALLOW_FILE_EDIT to false.
            add_filter('map_meta_cap', [self::class, 'denyFileEdit'], 10, 2);
        }

        if (!$config->allowXmlrpc) {
            if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
                self::forbidden('XML-RPC は無効になっています。');
            }
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('xmlrpc_methods', '__return_empty_array');
            add_filter('wp_headers', [self::class, 'removePingbackHeader']);
            remove_action('wp_head', 'rsd_link');
        }

        add_filter('rest_pre_dispatch', [self::class, 'protectUsersEndpoint'], 10, 3);
        add_action('template_redirect', [self::class, 'blockAuthorQuery'], 0);
        add_filter('wp_sitemaps_add_provider', [self::class, 'removeUsersSitemap'], 10, 2);
        add_filter('oembed_response_data', [self::class, 'stripOembedAuthor']);

        add_action('admin_init', [self::class, 'ensureUploadsHtaccess']);
        add_action('init', [self::class, 'maybeCheckUploadsHtaccess'], 30);
    }

    /** @param string[] $caps */
    public static function denyFileEdit($caps, $cap)
    {
        return in_array($cap, ['edit_plugins', 'edit_themes', 'edit_files'], true) ? ['do_not_allow'] : $caps;
    }

    public static function removePingbackHeader($headers)
    {
        unset($headers['X-Pingback']);
        return $headers;
    }

    /**
     * Anonymous visitors may not list users through the REST API (/wp/v2/users).
     * Logged-in editors still can; the block editor needs it.
     */
    public static function protectUsersEndpoint($result, $server, $request)
    {
        if ($result !== null || !($request instanceof \WP_REST_Request)) {
            return $result;
        }
        $route = (string) $request->get_route();
        if (preg_match('#^/wp/v2/users(/|$)#', $route) && !current_user_can('list_users')) {
            return new \WP_Error('rest_forbidden', 'ユーザー一覧は公開されていません。', ['status' => 401]);
        }
        return $result;
    }

    /** ?author=1 redirects to /author/<login-name>/ and reveals the login name. */
    public static function blockAuthorQuery(): void
    {
        if (isset($_GET['author']) && !is_user_logged_in()) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }

    public static function removeUsersSitemap($provider, $name)
    {
        return $name === 'users' ? false : $provider;
    }

    public static function stripOembedAuthor($data)
    {
        unset($data['author_name'], $data['author_url']);
        return $data;
    }

    public static function maybeCheckUploadsHtaccess(): void
    {
        if (!get_transient('wpguard_htaccess_check')) {
            set_transient('wpguard_htaccess_check', 1, self::HTACCESS_CHECK_INTERVAL);
            self::ensureUploadsHtaccess();
        }
    }

    public static function ensureUploadsHtaccess(): void
    {
        $uploads = wp_upload_dir(null, false);
        if (!empty($uploads['error']) || empty($uploads['basedir']) || !is_dir($uploads['basedir'])) {
            return;
        }
        $file = $uploads['basedir'] . '/.htaccess';
        $current = is_file($file) ? (string) @file_get_contents($file) : '';
        if (strpos($current, '# BEGIN ' . self::HTACCESS_MARKER) !== false && strpos($current, 'Require all denied') !== false) {
            return;
        }

        if (!function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
        if (!insert_with_markers($file, self::HTACCESS_MARKER, self::HTACCESS_RULES)) {
            error_log('[WPGuard] uploads/.htaccess を書き込めません: ' . $file);
            return;
        }

        if (get_option(self::HTACCESS_OPTION)) {
            Notifier::send(Notifier::WARNING, 'uploads/.htaccess の保護設定が消されていたため、作り直しました', [
                '📄 `' . Notifier::esc($file) . '`',
                'uploads 内で PHP を実行させようとした可能性があります。',
            ]);
        } else {
            update_option(self::HTACCESS_OPTION, 1, false);
        }
    }

    private static function forbidden(string $message): void
    {
        if (!headers_sent()) {
            status_header(403);
            header('Content-Type: text/plain; charset=utf-8');
        }
        echo $message;
        exit;
    }
}
