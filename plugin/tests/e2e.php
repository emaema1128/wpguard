<?php

/*
 * End-to-end test of WPGuard Sentinel against a real WordPress.
 *
 * Builds a WordPress site on SQLite (no MySQL needed), installs the mu-plugin,
 * runs it with PHP's built-in web server, and checks what reaches a fake Slack webhook.
 *
 *   php plugin/tests/e2e.php
 *
 * Needs network access to downloads.wordpress.org the first time (downloads are cached).
 * Work directory: $WPGUARD_E2E_DIR, default <tmp>/wpguard-e2e. Uses ports 8080 and 9999.
 *
 * To run the site on Apache with another PHP version (Docker, official php images):
 *   WPGUARD_E2E_IMAGE=php:7.4-apache php plugin/tests/e2e.php
 * WordPress then runs on Apache + that PHP, and .htaccess rules are checked for real.
 */

declare(strict_types=1);

const WP_VERSION = '7.1.5';
const SITE = 'http://127.0.0.1:8080';
const ADMIN_PASS = 'Correct-Horse-9';

$pluginSrc = dirname(__DIR__);
$work = getenv('WPGUARD_E2E_DIR') ?: sys_get_temp_dir() . '/wpguard-e2e';
$cache = "{$work}/cache";
$site = "{$work}/site";
$slackLog = "{$work}/slack.log";
$image = (string) getenv('WPGUARD_E2E_IMAGE');
const CONTAINER = 'wpguard-e2e';
const DB_CONTAINER = 'wpguard-e2e-db';
@mkdir($cache, 0777, true);

$passed = 0;
$failed = 0;
function check(bool $ok, string $label): void
{
    global $passed, $failed;
    $ok ? $passed++ : $failed++;
    echo ($ok ? '  ✓ ' : '  ✗ ') . $label . "\n";
}
function section(string $t): void
{
    echo "\n{$t}\n";
}
function sh(string $cmd): string
{
    exec($cmd . ' 2>&1', $out, $code);
    if ($code !== 0) {
        fwrite(STDERR, "コマンドが失敗しました: {$cmd}\n" . implode("\n", $out) . "\n");
        exit(2);
    }
    return implode("\n", $out);
}
function download(string $url, string $file): void
{
    if (!is_file($file)) {
        echo "ダウンロード中: {$url}\n";
        sh('curl -sSfL -m 300 -o ' . escapeshellarg($file) . ' ' . escapeshellarg($url));
    }
}
/** Runs PHP code inside WordPress (as a separate request). */
/** The PHP that runs WordPress: this machine's, or the one in the web server container. */
function phpCmd(): string
{
    global $image;
    return $image === '' ? 'php' : 'docker exec -u www-data ' . CONTAINER . ' php';
}
function wp(string $code): string
{
    global $site;
    return trim(sh(phpCmd() . ' ' . escapeshellarg(__DIR__ . '/wp-exec.php') . ' ' . escapeshellarg($site) . ' ' . escapeshellarg($code)));
}
/** @return array{status:int,headers:string,body:string} */
function http(string $method, string $path, array $opts = []): array
{
    $ch = curl_init(SITE . $path);
    $headers = [];
    if (isset($opts['ip'])) {
        $headers[] = 'X-Forwarded-For: ' . $opts['ip'];
    }
    $headers[] = 'Cookie: wordpress_test_cookie=WP%20Cookie%20check';
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
    ]);
    if (isset($opts['form'])) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($opts['form']));
    }
    if (isset($opts['body'])) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $opts['body']);
    }
    $raw = (string) curl_exec($ch);
    $size = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    return ['status' => (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), 'headers' => substr($raw, 0, $size), 'body' => substr($raw, $size)];
}
function login(string $user, string $pass, string $ip): array
{
    return http('POST', '/wp-login.php', ['ip' => $ip, 'form' => ['log' => $user, 'pwd' => $pass, 'testcookie' => '1', 'wp-submit' => 'Log In']]);
}
/** @return string[] Slack messages received since the last call */
function slack(): array
{
    global $slackLog;
    usleep(200000);
    $lines = is_file($slackLog) ? file($slackLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    file_put_contents($slackLog, '');
    return array_map(static fn ($l) => (string) json_decode($l, true)['text'], $lines);
}
function waitPort(int $port, int $seconds = 5): void
{
    for ($i = 0; $i < $seconds * 10; $i++) {
        $s = @fsockopen('127.0.0.1', $port, $e, $es, 0.2);
        if ($s) {
            fclose($s);
            return;
        }
        usleep(100000);
    }
    fwrite(STDERR, "ポート {$port} のサーバーが起動しません\n");
    exit(2);
}

// ---------------------------------------------------------------- build the site
// Local mode: PHP's built-in server + SQLite.
// Docker mode: Apache + the image's PHP + MariaDB, as on the production server.
download('https://downloads.wordpress.org/release/wordpress-' . WP_VERSION . '.zip', "{$cache}/wordpress.zip");
sh('rm -rf ' . escapeshellarg($site) . ' ' . escapeshellarg("{$work}/unzip"));
sh('unzip -q ' . escapeshellarg("{$cache}/wordpress.zip") . ' -d ' . escapeshellarg("{$work}/unzip"));
rename("{$work}/unzip/wordpress", $site);

if ($image === '') {
    download('https://downloads.wordpress.org/plugin/sqlite-database-integration.latest-stable.zip', "{$cache}/sqlite.zip");
    sh('unzip -q ' . escapeshellarg("{$cache}/sqlite.zip") . ' -d ' . escapeshellarg("{$site}/wp-content/plugins"));
    $sqliteDir = "{$site}/wp-content/plugins/sqlite-database-integration";
    file_put_contents("{$site}/wp-content/db.php", str_replace(
        ['{SQLITE_IMPLEMENTATION_FOLDER_PATH}', '{SQLITE_PLUGIN}'],
        [$sqliteDir, 'sqlite-database-integration/load.php'],
        file_get_contents("{$sqliteDir}/db.copy"),
    ));
    [$dbUser, $dbPass, $dbHost] = ['', '', 'localhost'];
} else {
    [$dbUser, $dbPass, $dbHost] = ['root', 'root', '127.0.0.1:3306'];
}
@mkdir("{$site}/wp-content/uploads", 0777, true);

$salts = '';
foreach (['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'] as $k) {
    $salts .= "define('{$k}', '" . bin2hex(random_bytes(24)) . "');\n";
}
file_put_contents("{$site}/wp-config.php", <<<PHP
<?php
define('DB_NAME', 'wp');
define('DB_USER', '{$dbUser}');
define('DB_PASSWORD', '{$dbPass}');
define('DB_HOST', '{$dbHost}');
\$table_prefix = 'wp_';
{$salts}
define('WP_HOME', 'http://127.0.0.1:8080');
define('WP_SITEURL', 'http://127.0.0.1:8080');
define('DISABLE_WP_CRON', true);
define('AUTOMATIC_UPDATER_DISABLED', true);
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_ACCESSIBLE_HOSTS', '127.0.0.1');

define('WPGUARD_SHARED_CONFIG', '{$work}/sentinel.php');
define('WPGUARD_SITE_NAME', 'e2e.example');
define('WPGUARD_SLACK_MENTION', '');

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
require_once ABSPATH . 'wp-settings.php';
PHP);

// Shared settings, made from the example file exactly as an operator would.
$shared = strtr((string) file_get_contents("{$pluginSrc}/sentinel.example.php"), [
    "'WPGUARD_SLACK_WEBHOOK' => ''" => "'WPGUARD_SLACK_WEBHOOK' => 'http://127.0.0.1:9999/hook'",
    "'WPGUARD_LOGIN_MAX_RETRIES' => 5" => "'WPGUARD_LOGIN_MAX_RETRIES' => 3",
    "'WPGUARD_TRUSTED_PROXIES' => []" => "'WPGUARD_TRUSTED_PROXIES' => ['127.0.0.1']",
    "'WPGUARD_SLACK_MENTION' => '<!channel>'" => "'WPGUARD_SLACK_MENTION' => '<!here>'",
]);
file_put_contents("{$work}/sentinel.php", $shared);

// ---------------------------------------------------------------- servers
file_put_contents($slackLog, '');
$env = array_merge(getenv(), ['MOCK_SLACK_LOG' => $slackLog]);
$null = ['file', '/dev/null', 'w'];
$slackSrv = proc_open(['php', '-S', '127.0.0.1:9999', __DIR__ . '/mock-slack.php'], [0 => ['pipe', 'r'], 1 => $null, 2 => $null], $p1, null, $env);
if ($image === '') {
    $wpSrv = proc_open(['php', '-S', '127.0.0.1:8080', '-t', $site], [0 => ['pipe', 'r'], 1 => $null, 2 => $null], $p2, $site);
} else {
    $wpSrv = null;
    exec('docker rm -f ' . CONTAINER . ' ' . DB_CONTAINER . ' 2>/dev/null');
    // Containers share this machine's network, so Apache can reach the fake Slack on 127.0.0.1.
    sh('docker run -d --name ' . DB_CONTAINER . ' --network host -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=wp mariadb:11');
    sh('chmod -R a+rwX ' . escapeshellarg($site));
    file_put_contents("{$work}/apache.conf", <<<CONF
    Listen 8080
    <VirtualHost *:8080>
        DocumentRoot "{$site}"
        <Directory "{$site}">
            AllowOverride All
            Require all granted
        </Directory>
    </VirtualHost>
    CONF);
    sh('docker run -d --name ' . CONTAINER . ' --network host'
        . ' -v ' . escapeshellarg("{$work}:{$work}") . ' -v ' . escapeshellarg(__DIR__ . ':' . __DIR__)
        . ' ' . escapeshellarg($image)
        . ' sh -c ' . escapeshellarg("docker-php-ext-install mysqli >/dev/null 2>&1; echo > /etc/apache2/ports.conf && cp {$work}/apache.conf /etc/apache2/sites-enabled/000-default.conf && exec apache2-foreground"));
}
register_shutdown_function(static function () use ($slackSrv, $wpSrv): void {
    proc_terminate($slackSrv);
    if ($wpSrv !== null) {
        proc_terminate($wpSrv);
    } else {
        exec('docker rm -f ' . CONTAINER . ' ' . DB_CONTAINER . ' 2>/dev/null');
    }
});
waitPort(9999);
waitPort(8080, 300);
if ($image !== '') {
    for ($i = 0; $i < 120 && trim((string) shell_exec('docker exec ' . DB_CONTAINER . ' mariadb -uroot -proot -e "select 1" 2>/dev/null | tail -1')) !== '1'; $i++) {
        sleep(1);
    }
    echo 'Web サーバー: ' . str_replace("\n", ' / ', trim(sh('docker exec ' . CONTAINER . ' sh -c ' . escapeshellarg('apache2 -v | head -1; php -v | head -1')))) . "\n";
    echo 'DB: MariaDB ' . trim(sh('docker exec ' . DB_CONTAINER . ' mariadb -uroot -proot -N -e "select version()"')) . "\n";
}

sh(phpCmd() . ' -r ' . escapeshellarg(
    "define('WP_INSTALLING', true); \$_SERVER['HTTP_HOST']='127.0.0.1:8080'; require '{$site}/wp-load.php';"
    . "require ABSPATH . 'wp-admin/includes/upgrade.php';"
    . "wp_install('E2E', 'admin', 'admin@example.com', true, '', '" . ADMIN_PASS . "');"
));

// Install the mu-plugin the way it is installed on the server.
@mkdir("{$site}/wp-content/mu-plugins");
copy("{$pluginSrc}/wpguard-sentinel.php", "{$site}/wp-content/mu-plugins/wpguard-sentinel.php");
sh('cp -r ' . escapeshellarg("{$pluginSrc}/wpguard-sentinel") . ' ' . escapeshellarg("{$site}/wp-content/mu-plugins/"));
$bobId = (int) wp("echo wp_insert_user(['user_login' => 'bob', 'user_pass' => 'bob-pass-1', 'user_email' => 'bob@example.com', 'role' => 'subscriber']);");

// ---------------------------------------------------------------- tests
section('有効化の確認');
$r = http('GET', '/');
check($r['status'] === 200, 'サイトが表示される');
check(wp("echo defined('WPGUARD_SENTINEL_VERSION') ? 'loaded' : 'no';") === 'loaded', 'mu-plugin が読み込まれている');
check(slack() === [], '導入直後は何も通知しない');

section('P-06: uploads での PHP 実行を禁止');
$ht = "{$site}/wp-content/uploads/.htaccess";
check(is_file($ht) && str_contains((string) file_get_contents($ht), 'Require all denied'), 'uploads/.htaccess を自動で作成する');
$before = filemtime($ht);
wp("delete_transient('wpguard_htaccess_check');");
http('GET', '/');
clearstatcache();
check(filemtime($ht) === $before, '設定済みなら書き換えない (監視エージェントが誤報しないように)');
wp("unlink('{$ht}'); delete_transient('wpguard_htaccess_check');");
http('GET', '/');
$m = slack();
check(is_file($ht) && count($m) === 1 && str_contains($m[0], '作り直しました'), '消されたら作り直して🟡警告を通知');

if ($image !== '') {
    section('P-06: Apache で uploads の PHP が実行されないこと');
    $up = "{$site}/wp-content/uploads/2026";
    @mkdir($up, 0777, true);
    file_put_contents("{$up}/shell.php", '<?php echo "EXECUTED";');
    file_put_contents("{$up}/shell.PHP", '<?php echo "EXECUTED";');
    file_put_contents("{$up}/shell.phtml", '<?php echo "EXECUTED";');
    file_put_contents("{$up}/photo.jpg", 'JPEGDATA');
    file_put_contents("{$site}/control.php", '<?php echo "EXECUTED";');
    check(http('GET', '/control.php')['body'] === 'EXECUTED', '(対照: uploads の外の PHP は実行される)');
    foreach (['shell.php', 'shell.PHP', 'shell.phtml'] as $f) {
        $r = http('GET', "/wp-content/uploads/2026/{$f}");
        check($r['status'] === 403 && !str_contains($r['body'], 'EXECUTED'), "uploads/{$f} は 403 で実行されない");
    }
    check(http('GET', '/wp-content/uploads/2026/photo.jpg')['status'] === 200, '画像は普通に表示できる');
    unlink("{$site}/control.php");
}

section('P-05: XML-RPC とユーザー名の列挙を防ぐ');
$r = http('POST', '/xmlrpc.php', ['body' => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>']);
check($r['status'] === 403, 'xmlrpc.php は 403');
check(!str_contains($r['body'], 'methodResponse'), 'XML-RPC の処理は動かない');
$r = http('GET', '/?rest_route=/wp/v2/users');
check($r['status'] === 401 && !str_contains($r['body'], '"slug":"admin"'), 'REST API のユーザー一覧は 401');
$r = http('GET', '/?rest_route=/wp/v2/users/1');
check($r['status'] === 401, 'REST API のユーザー個別取得も 401');
$r = http('GET', '/?rest_route=/wp/v2/posts');
check($r['status'] === 200, 'ほかの REST API は使える');
$r = http('GET', '/?author=1');
check($r['status'] === 301 && !preg_match('#Location: .*/author/#i', $r['headers']), '?author=1 はトップへ転送 (ユーザー名を出さない)');
$r = http('GET', '/?rest_route=/oembed/1.0/embed&url=' . urlencode(SITE . '/?p=1'));
check($r['status'] === 200 && !str_contains($r['body'], 'author_name'), 'oEmbed に投稿者名を出さない');

section('P-04: 管理画面でのファイル編集を禁止');
check(wp("wp_set_current_user(1); echo current_user_can('edit_plugins') || current_user_can('edit_themes') ? 'yes' : 'no';") === 'no', '管理者でもプラグイン/テーマを編集できない');
check(wp("wp_set_current_user(1); echo current_user_can('activate_plugins') ? 'yes' : 'no';") === 'yes', 'ほかの管理者権限はそのまま');

section('P-01: ログイン試行の制限');
$r = login('admin', 'wrong', '203.0.113.10');
check(str_contains($r['body'], 'ユーザー名またはパスワードが正しくありません'), 'パスワード違いは共通のメッセージ');
$r2 = login('nobody', 'wrong', '203.0.113.99');
check(str_contains($r2['body'], 'ユーザー名またはパスワードが正しくありません') && !str_contains($r2['body'], 'nobody'), '存在しないユーザーでも同じメッセージ (ユーザー名を探らせない)');
check(slack() === [], '失敗が 1〜2 回なら通知しない');
login('admin', 'wrong2', '203.0.113.10');
login('editor', 'wrong3', '203.0.113.10');
$m = slack();
check(count($m) === 1 && str_contains($m[0], 'ロックしました') && str_contains($m[0], '203.0.113.10') && str_contains($m[0], '`admin`') && str_contains($m[0], '`editor`'), '3 回失敗で IP をロックし、試されたユーザー名と一緒に通知');
$r = login('admin', ADMIN_PASS, '203.0.113.10');
check(str_contains($r['body'], '一時的にログインできません') && !str_contains($r['headers'], 'wordpress_logged_in'), 'ロック中は正しいパスワードでもログインできない');
$r = login('admin', ADMIN_PASS, '198.51.100.7');
check($r['status'] === 302 && str_contains($r['headers'], 'wordpress_logged_in'), 'ほかの IP からは普通にログインできる');
check(slack() === [], '導入後初めての管理者ログインは IP を覚えるだけ');
login('admin', ADMIN_PASS, '198.51.100.7');
check(slack() === [], '覚えた IP からのログインは通知しない');
login('admin', ADMIN_PASS, '198.51.100.8');
$m = slack();
check(count($m) === 1 && str_contains($m[0], '新しい IP アドレスからログイン') && str_contains($m[0], '198.51.100.8'), '管理者が新しい IP からログインしたら🟡警告');
login('bob', 'bob-pass-1', '198.51.100.9');
check(slack() === [], '管理者以外のログインは通知しない');
check(wp("\$_SERVER['REMOTE_ADDR'] = '192.0.2.1'; \$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4'; WPGuard\\Sentinel\\ClientIp::configure(['127.0.0.1']); echo WPGuard\\Sentinel\\ClientIp::get();") === '192.0.2.1', '信頼していない接続元の X-Forwarded-For は無視する (偽装でロックを逃れられない)');

section('P-02: 管理者の追加・昇格');
wp("wp_insert_user(['user_login' => 'mallory', 'user_pass' => wp_generate_password(), 'user_email' => 'mallory@example.com', 'role' => 'administrator']);");
$m = slack();
check(count($m) === 1 && str_contains($m[0], '🔴') && str_contains($m[0], '管理者アカウントが作成されました') && str_contains($m[0], 'mallory'), '管理者の作成を🔴緊急で通知 (1 通だけ)');
check(str_contains($m[0] ?? '', 'ログインしていない状態'), '誰が操作したかを表示');
check(!str_contains($m[0] ?? '', '<!here>'), 'サイトの wp-config.php の設定が、共通設定より優先される (メンションなし)');
wp("wp_insert_user(['user_login' => 'carol', 'user_pass' => wp_generate_password(), 'user_email' => 'carol@example.com', 'role' => 'author']);");
check(slack() === [], '管理者以外の作成は通知しない');
wp("(new WP_User({$bobId}))->set_role('administrator');");
$m = slack();
check(count($m) === 1 && str_contains($m[0], '昇格しました') && str_contains($m[0], 'bob'), '管理者への昇格を🔴緊急で通知');
wp(<<<'PHP'
global $wpdb;
$wpdb->insert($wpdb->users, ['user_login' => 'ghost', 'user_pass' => 'x', 'user_nicename' => 'ghost', 'user_email' => 'ghost@example.com', 'user_registered' => '2026-01-01 00:00:00', 'display_name' => 'ghost']);
$wpdb->insert($wpdb->usermeta, ['user_id' => $wpdb->insert_id, 'meta_key' => $wpdb->prefix . 'capabilities', 'meta_value' => serialize(['administrator' => true])]);
delete_transient('wpguard_admin_check');
PHP);
check(slack() === [], '(DB の直接操作はフックでは見えない)');
http('GET', '/');
$m = slack();
check(count($m) === 1 && str_contains($m[0], 'WordPress を通さずに追加') && str_contains($m[0], 'ghost'), 'DB に直接追加された管理者も、定期チェックで🔴緊急で通知');

section('P-03: プラグインの有効化');
wp("update_option('active_plugins', array_merge((array) get_option('active_plugins'), ['hello.php']));");
$m = slack();
check(count($m) === 1 && str_contains($m[0], '🔴') && str_contains($m[0], 'ログインしていない状態でプラグインが有効化') && str_contains($m[0], 'Hello Dolly'), 'コードから勝手に有効化されたら🔴緊急');
wp("wp_set_current_user(1); require_once ABSPATH . 'wp-admin/includes/plugin.php'; deactivate_plugins('hello.php');");
check(slack() === [], '無効化は🔵情報なので通知しない (既定)');
wp("wp_set_current_user(1); require_once ABSPATH . 'wp-admin/includes/plugin.php'; activate_plugin('hello.php');");
$m = slack();
check(count($m) === 1 && str_contains($m[0], '🟡') && str_contains($m[0], 'プラグインが有効化されました') && str_contains($m[0], 'admin'), '管理者による有効化は🟡警告');
wp("wp_set_current_user(1); switch_theme('twentytwentyfour');");
$m = slack();
check(count($m) === 1 && str_contains($m[0], 'テーマが変更されました'), 'テーマの変更を🟡警告で通知');

section('P-08: WP-Cron の監視');
$mu = "{$site}/wp-content/mu-plugins";
/** Runs the 5-minute cron check now and returns what reached Slack. */
$cronCheck = static function (): array {
    wp("delete_transient('wpguard_cron_check');");
    http('GET', '/');
    return slack();
};
check($cronCheck() === [], 'WordPress 本体の定期実行は通知しない (初回に記録済み)');

@mkdir("{$site}/wp-content/plugins/cronplug");
file_put_contents("{$site}/wp-content/plugins/cronplug/cronplug.php", <<<'P'
<?php
/* Plugin Name: Cron Plug */
add_action('cronplug_daily', function () {});
register_activation_hook(__FILE__, function () { wp_schedule_event(time() + 3600, 'daily', 'cronplug_daily'); });
P);
wp("wp_set_current_user(1); require_once ABSPATH . 'wp-admin/includes/plugin.php'; activate_plugin('cronplug/cronplug.php');");
slack(); // the activation itself is reported by P-03
check($cronCheck() === [], 'プラグインが登録した定期実行は、記録だけして通知しない');

file_put_contents("{$mu}/zz-cache.php", "<?php\neval('add_action(\"wp_cache_gc_x\", function () {});');\n");
wp("wp_schedule_event(time() + 600, 'hourly', 'wp_cache_gc_x');");
$m = $cronCheck();
check(count($m) === 1 && str_contains($m[0], '🔴') && str_contains($m[0], 'wp_cache_gc_x') && str_contains($m[0], 'eval() で作られた'), 'eval で作られた処理の定期実行を🔴緊急で通知');
check(str_contains($m[0] ?? '', '1 時間ごと'), '実行の間隔を表示');
check(str_contains($m[0] ?? '', '次回: ' . (new DateTime('@' . (time() + 600)))->setTimezone(new DateTimeZone('Asia/Tokyo'))->format('m/d H')), '次回の実行日時を日本時間で表示');
echo "\n" . preg_replace('/^/m', '      | ', $m[0] ?? '') . "\n";

@mkdir("{$site}/wp-content/uploads/2026", 0777, true);
file_put_contents("{$site}/wp-content/uploads/2026/helper.php", "<?php\nfunction wpg_helper_job() {}\nadd_action('wp_media_cleanup', 'wpg_helper_job');\n");
file_put_contents("{$mu}/zz-loader.php", "<?php\n@include WP_CONTENT_DIR . '/uploads/2026/helper.php';\n");
wp("wp_schedule_event(time() + 600, 'twicedaily', 'wp_media_cleanup');");
$m = $cronCheck();
check(count($m) === 1 && str_contains($m[0], '🔴') && str_contains($m[0], 'wp-content/uploads/2026/helper.php:2'), 'uploads にあるコードの定期実行を🔴緊急で通知 (ファイルと行番号を表示)');

wp("\$c = _get_cron_array(); \$c[time() + 120]['a3f9c2e1b7d4a6e8'][md5('x')] = ['schedule' => false, 'args' => ['https://evil.example/p.txt']]; _set_cron_array(\$c);");
$m = $cronCheck();
check(count($m) === 1 && str_contains($m[0], '🔴') && str_contains($m[0], '見つかりません') && str_contains($m[0], '引数に URL') && str_contains($m[0], 'ランダムな文字列') && str_contains($m[0], '1 回だけ'), 'DB に直接書き込まれた定期実行を🔴緊急で通知 (処理が見つからない・怪しい引数・ランダムな名前)');

file_put_contents("{$mu}/zz-site.php", "<?php\nfunction mysite_cleanup() {}\nadd_action('mysite_cleanup', 'mysite_cleanup');\n");
wp("wp_schedule_event(time() + 600, 'daily', 'mysite_cleanup');");
$m = $cronCheck();
check(count($m) === 1 && str_contains($m[0], '🟡') && str_contains($m[0], 'wp-content/mu-plugins/zz-site.php'), 'mu-plugins の処理の定期実行は🟡警告');
check($cronCheck() === [], '同じ処理は二度通知しない');
foreach (['zz-cache.php', 'zz-loader.php', 'zz-site.php'] as $f) {
    unlink("{$mu}/{$f}");
}

section('P-07: 二要素認証');
require_once "{$pluginSrc}/wpguard-sentinel/src/Totp.php";
/** Value of the last logged-in cookie the response sets ('' when it clears it, null when none). */
$authCookie = static function (array $r): ?string {
    preg_match_all('/^Set-Cookie: wordpress_logged_in_[^=]+=([^;]*)/mi', $r['headers'], $m);
    return $m[1] === [] ? null : trim(urldecode(end($m[1])));
};
$location = static fn (array $r): string => preg_match('/^Location: (\S+)/mi', $r['headers'], $m) ? $m[1] : '';
$token = static fn (string $loc): string => preg_match('/wpguard_token=([a-f0-9]+)/', $loc, $m) ? $m[1] : '';
$twofa = static fn (string $tok, string $step, string $code, string $ip) => http('POST', '/wp-login.php?action=wpguard_2fa', ['ip' => $ip, 'form' => ['wpguard_token' => $tok, 'wpguard_step' => $step, 'wpguard_code' => $code]]);

$r = login('admin', ADMIN_PASS, '198.51.100.7');
check($r['status'] === 302 && $authCookie($r) !== '' && !str_contains($location($r), 'wpguard_2fa'), '猶予期間中は、設定していなくてもログインできる');
wp("update_user_meta(1, 'wpguard_2fa_grace_start', time() - 8 * DAY_IN_SECONDS);");

$r = login('admin', ADMIN_PASS, '198.51.100.7');
$tok = $token($location($r));
check($r['status'] === 302 && $tok !== '' && $authCookie($r) === '', '猶予期間を過ぎたら、パスワードが正しくてもログインを止めて設定画面へ (ログイン状態は消す)');
$page = http('GET', '/wp-login.php?action=wpguard_2fa&wpguard_token=' . $tok, ['ip' => '198.51.100.7']);
preg_match('/user-select:all">([A-Z2-7 ]{20,})<\/code>/', $page['body'], $sm);
$secret = str_replace(' ', '', $sm[1] ?? '');
check(strlen($secret) === 32 && str_contains($page['body'], 'この設定は必須です'), '設定キーと手順を表示する');
check(str_contains($page['body'], 'otpauth://totp/'), 'スマホでタップすればアプリに追加できるリンクも表示する');
$r = $twofa($tok, 'enroll', '000000', '198.51.100.21');
check(str_contains($r['body'], 'コードが正しくありません') && $authCookie($r) === null, '違うコードでは設定できない');
$step = intdiv(time(), 30);
$r = $twofa($tok, 'enroll', WPGuard\Sentinel\Totp::code($secret, $step), '198.51.100.7');
preg_match('/<pre[^>]*>([a-z0-9\-\n]+)<\/pre>/', $r['body'], $rm);
$codes = isset($rm[1]) ? explode("\n", trim($rm[1])) : [];
check(count($codes) === 10 && preg_match('/^[a-z0-9]{4}-[a-z0-9]{4}$/', $codes[0] ?? '') === 1, '正しいコードで設定でき、予備コードを 10 個表示する');
check($authCookie($r) === null, '(予備コードを見ている間は、まだログインしていない)');
$r = $twofa($tok, 'finish', '', '198.51.100.7');
check($r['status'] === 302 && ($authCookie($r) ?? '') !== '', '「ログインを続ける」でログインできる');
slack();

$r = login('admin', ADMIN_PASS, '198.51.100.7');
$tok = $token($location($r));
$page = http('GET', '/wp-login.php?action=wpguard_2fa&wpguard_token=' . $tok, ['ip' => '198.51.100.7']);
check($tok !== '' && $authCookie($r) === '' && str_contains($page['body'], '確認コードの入力'), '設定後は、毎回パスワードの次に確認コードを求める');
$r = $twofa($tok, 'code', WPGuard\Sentinel\Totp::code($secret, $step), '198.51.100.22');
check(str_contains($r['body'], 'コードが正しくありません'), '一度使ったコードは使えない (盗み見たコードの再利用を防ぐ)');
$r = $twofa($tok, 'code', WPGuard\Sentinel\Totp::code($secret, $step + 1), '198.51.100.7');
check($r['status'] === 302 && ($authCookie($r) ?? '') !== '', '新しいコードならログインできる');

$r = login('admin', ADMIN_PASS, '198.51.100.7');
$tok = $token($location($r));
$r = $twofa($tok, 'code', strtoupper($codes[0]), '198.51.100.7');
$m = slack();
check($r['status'] === 302 && ($authCookie($r) ?? '') !== '', '予備コードでもログインできる (大文字でも可)');
check(count($m) === 1 && str_contains($m[0], '予備コードでログインしました') && str_contains($m[0], '残りの予備コード: 9 個'), '予備コードを使ったら🟡警告で知らせる');
$r = login('admin', ADMIN_PASS, '198.51.100.7');
$r = $twofa($token($location($r)), 'code', $codes[0], '198.51.100.23');
check(str_contains($r['body'], 'コードが正しくありません'), '使った予備コードは二度と使えない');

$r = login('admin', ADMIN_PASS, '198.51.100.7');
$tok = $token($location($r));
foreach (['000001', '000002', '000003'] as $bad) {
    $twofa($tok, 'code', $bad, '203.0.113.50');
}
$m = slack();
$r = $twofa($tok, 'code', WPGuard\Sentinel\Totp::code($secret, $step + 2), '203.0.113.50');
check(str_contains($r['body'], '一時的にログインできません') && $authCookie($r) === null, 'コードを 3 回間違えた IP はロックされ、正しいコードでも入れない (総当たり対策)');
check(count($m) === 1 && str_contains($m[0], 'ロックしました'), 'ロックを Slack に通知する');
$r = login('admin', ADMIN_PASS, '198.51.100.7');
$tok = $token($location($r));
foreach (range(60, 64) as $i) {
    $last = $twofa($tok, 'code', '999999', "198.51.100.{$i}");
}
check(str_contains($location($last), 'wpguard_expired'), '1 回のログインで 5 回間違えたら、パスワードの入力からやり直し');
check(http('GET', '/wp-login.php?action=wpguard_2fa&wpguard_token=' . str_repeat('ab', 32))['status'] === 302, '偽のトークンでは確認画面に入れない');
slack();

wp("wp_set_password('carol-pass-1', get_user_by('login', 'carol')->ID);");
$r = login('carol', 'carol-pass-1', '198.51.100.30');
check($r['status'] === 302 && ($authCookie($r) ?? '') !== '' && !str_contains($location($r), 'wpguard_2fa'), '管理者以外 (投稿者) には求めない');
check(wp("echo WPGuard\\Sentinel\\TwoFactor::required(get_user_by('login', 'carol')) ? 'yes' : 'no';") === 'no', '(必須なのは管理者だけ)');
// (WordPress itself only offers application passwords over HTTPS, so ask the filter directly.)
$appPw = static fn (string $login): string => wp("echo apply_filters('wp_is_application_passwords_available_for_user', true, get_user_by('login', '{$login}')) ? 'yes' : 'no';");
check($appPw('admin') === 'no', '管理者はアプリケーションパスワードを使えない (二要素認証の抜け道をふさぐ)');
check($appPw('carol') === 'yes', '管理者以外は、これまでどおり使える');
slack();

section('Slack が落ちていたら後で再送');
touch("{$slackLog}.down");
wp("wp_insert_user(['user_login' => 'eve', 'user_pass' => wp_generate_password(), 'user_email' => 'eve@example.com', 'role' => 'administrator']);");
unlink("{$slackLog}.down");
check(slack() === [] && wp("echo count((array) get_option('wpguard_pending_notifications'));") === '1', '送れなかった通知を保存する');
http('GET', '/');
check(slack() === [], '再送は 5 分おき (毎回のアクセスでは試さない)');
wp("delete_transient('wpguard_retry_lock');");
http('GET', '/');
$m = slack();
check(count($m) === 1 && str_contains($m[0], 'eve') && wp("echo count((array) get_option('wpguard_pending_notifications'));") === '0', '時間が経てば再送する');

echo "\n{$passed} 件成功, {$failed} 件失敗\n";
exit($failed === 0 ? 0 : 1);
