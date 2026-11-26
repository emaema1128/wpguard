<?php

/*
 * A-09 database scan tests against a real MariaDB (started with Docker).
 *
 *   php tests/dbscan.php
 *
 * Uses port 3307. Skips (exit 0) when Docker is not available.
 */

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use WPGuard\App;
use WPGuard\Checksums\NullChecksums;
use WPGuard\Config;
use WPGuard\Logger;
use WPGuard\Notifier\Message;
use WPGuard\Notifier\Notifier;

final class CaptureNotifier implements Notifier
{
    /** @var Message[] */
    public array $sent = [];

    public function send(Message $message): bool
    {
        $this->sent[] = $message;
        return true;
    }

    /** @return string[] */
    public function take(): array
    {
        $m = array_map(static fn (Message $x) => $x->text, $this->sent);
        $this->sent = [];
        return $m;
    }
}

$passed = 0;
$failed = 0;
function check(bool $cond, string $label): void
{
    global $passed, $failed;
    $cond ? $passed++ : $failed++;
    echo ($cond ? '  ✓ ' : '  ✗ ') . $label . "\n";
}
function section(string $t): void
{
    echo "\n{$t}\n";
}

const CONTAINER = 'wpguard-test-mariadb';
const PORT = 3307;
const PASS = "p'a\"ss\\word";

exec('docker info >/dev/null 2>&1', $_, $code);
if ($code !== 0) {
    echo "Docker が使えないため、DB のテストを飛ばします\n";
    exit(0);
}
exec('docker rm -f ' . CONTAINER . ' >/dev/null 2>&1');
exec('docker run -d --name ' . CONTAINER . ' --network host -e MARIADB_ROOT_PASSWORD=root mariadb:11 --port=' . PORT . ' 2>&1', $out, $code);
if ($code !== 0) {
    echo "MariaDB を起動できません:\n" . implode("\n", $out) . "\n";
    exit(1);
}
register_shutdown_function(static fn () => exec('docker rm -f ' . CONTAINER . ' >/dev/null 2>&1'));

$root = null;
for ($i = 0; $i < 120 && $root === null; $i++) {
    try {
        $root = new PDO('mysql:host=127.0.0.1;port=' . PORT, 'root', 'root', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    } catch (PDOException) {
        sleep(1);
    }
}
if ($root === null) {
    echo "MariaDB に接続できません\n";
    exit(1);
}
echo 'MariaDB ' . $root->query('SELECT VERSION()')->fetchColumn() . "\n";

// ---------------------------------------------------------------- a WordPress-like database
$root->exec('CREATE DATABASE site1 CHARACTER SET utf8mb4');
$root->exec("CREATE USER 'wp1'@'%' IDENTIFIED BY " . $root->quote(PASS));
$root->exec("GRANT SELECT ON site1.* TO 'wp1'@'%'"); // read-only is enough
$root->exec('USE site1');
$root->exec('CREATE TABLE wp_options (option_id BIGINT AUTO_INCREMENT PRIMARY KEY, option_name VARCHAR(191) UNIQUE, option_value LONGTEXT, autoload VARCHAR(20))');
$root->exec('CREATE TABLE wp_posts (ID BIGINT AUTO_INCREMENT PRIMARY KEY, post_title TEXT, post_content LONGTEXT, post_type VARCHAR(20), post_status VARCHAR(20))');
$root->exec('CREATE TABLE wp_users (ID BIGINT AUTO_INCREMENT PRIMARY KEY, user_login VARCHAR(60))');
$root->exec('CREATE TABLE wp_usermeta (umeta_id BIGINT AUTO_INCREMENT PRIMARY KEY, user_id BIGINT, meta_key VARCHAR(255), meta_value LONGTEXT)');

function opt(PDO $db, string $name, string $value): void
{
    $db->prepare('INSERT INTO site1.wp_options (option_name, option_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE option_value = VALUES(option_value)')->execute([$name, $value]);
}
function post(PDO $db, string $title, string $content, string $type = 'post'): int
{
    $db->prepare("INSERT INTO site1.wp_posts (post_title, post_content, post_type, post_status) VALUES (?, ?, ?, 'publish')")->execute([$title, $content, $type]);
    return (int) $db->lastInsertId();
}
function admin(PDO $db, string $login): void
{
    $db->prepare('INSERT INTO site1.wp_users (user_login) VALUES (?)')->execute([$login]);
    $id = (int) $db->lastInsertId();
    $db->prepare("INSERT INTO site1.wp_usermeta (user_id, meta_key, meta_value) VALUES (?, 'wp_capabilities', 'a:1:{s:13:\"administrator\";b:1;}')")->execute([$id]);
}

opt($root, 'siteurl', 'https://site1.example');
opt($root, 'home', 'https://site1.example');
opt($root, 'blogname', 'Site 1');
admin($root, 'admin');
post($root, 'こんにちは', '<p>本文</p><script async src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>');
post($root, '自サイト', '<script src="https://site1.example/wp-content/x.js"></script><script src="//cdn.site1.example/y.js"></script>');
post($root, '広告', '<script src="https://ads.partner-network.example/tag.js"></script>');
// Already compromised before monitoring starts.
opt($root, 'widget_custom_html', serialize([2 => ['content' => '<script>eval(atob("YWxlcnQoMSk="))</script>']]));
post($root, '古いリビジョン', '<script>eval(atob("eA=="))</script>', 'revision');

// ---------------------------------------------------------------- the site on disk
$tmp = sys_get_temp_dir() . '/wpguard-dbtest-' . bin2hex(random_bytes(4));
$site = "{$tmp}/www/site1";
mkdir("{$site}/wp-includes", 0777, true);
mkdir("{$site}/wp-content");
file_put_contents("{$site}/wp-includes/version.php", "<?php \$wp_version = '7.1.5';");
$escaped = str_replace(['\\', "'"], ['\\\\', "\\'"], PASS);
file_put_contents("{$site}/wp-config.php", "<?php\ndefine('DB_NAME', 'site1');\ndefine('DB_USER', 'wp1');\ndefine('DB_PASSWORD', '{$escaped}');\ndefine('DB_HOST', '127.0.0.1:" . PORT . "');\n\$table_prefix = 'wp_';\n");

$n = new CaptureNotifier();
$app = new App(
    Config::fromArray(['roots' => ["{$tmp}/www"], 'data_dir' => "{$tmp}/data", 'log_file' => "{$tmp}/w.log", 'slack' => ['mention_critical' => '']]),
    $n, new Logger("{$tmp}/w.log"), false, new NullChecksums(),
);
$t = time();

/** @return array<string,array> rule => finding row, for the findings recorded by the last scan */
function lastFindings(App $app, int $since): array
{
    $out = [];
    foreach ($app->db->openFindings() as $f) {
        if ((int) $f['detected_at'] >= $since) {
            $out[$f['rule']] = $f;
        }
    }
    return $out;
}

// ---------------------------------------------------------------- tests
section('初回: 導入時点の DB を検査');
$app->scan(false, null, $t);
$m = $n->take();
$all = $app->db->findingCountsSince(0)[1] ?? [];
$open = lastFindings($app, $t);
check(isset($open['js-eval-decode']) && $open['js-eval-decode']['path'] === 'db:options/widget_custom_html', 'ウィジェットに埋め込まれていた難読化スクリプトを🔴緊急で検知');
check(!str_contains(implode("\n", $m), 'revision') && count(array_filter($app->db->openFindings(), static fn ($f) => str_starts_with($f['path'], 'db:posts'))) === 0, 'リビジョンは検査しない / 既存の外部スクリプトは通知しない');
check(($all['info'] ?? 0) === 1, '既存の外部スクリプト (広告) は🔵情報として記録だけする');
check(str_contains(implode("\n", $m), '設定 (widget_custom_html)に難読化された JavaScript'), 'Slack に通知する');
check(!str_contains(implode("\n", $m), 'wpguard quarantine'), 'DB の検知には隔離のコマンドを案内しない');
echo "\n" . preg_replace('/^/m', '      | ', end($m)) . "\n";

section('変更なし');
$app->dbScan(null, $t += 60);
check($n->take() === [], '同じものを再報告しない');

section('投稿にスクリプトを埋め込まれる');
$evil = post($root, '新着情報', '<p>お知らせ</p><script>document.write(unescape("%3Cscript%20src%3D..."))</script>');
$cdn = post($root, 'キャンペーン', '<script src="https://cdn-js-delivery.example/jquery.min.js"></script>');
$ip = post($root, 'ip', '<script type="text/javascript" src="http://185.0.2.44/x.js"></script>');
$ifr = post($root, 'iframe', '<iframe src="https://spam.example/" width="0" height="0" frameborder="0"></iframe>');
post($root, '計測', '<script src="https://www.google-analytics.com/analytics.js"></script>');
$app->dbScan(null, $t += 60);
$found = lastFindings($app, $t);
check(isset($found['js-write-decode']) && $found['js-write-decode']['path'] === "db:posts/{$evil}" && $found['js-write-decode']['severity'] === 'critical', 'document.write(unescape(...)) を🔴緊急で検知');
check(isset($found['script-from-ip']) && $found['script-from-ip']['severity'] === 'critical', 'IP アドレスから読み込むスクリプトを🔴緊急で検知');
check(isset($found['script-external']) && $found['script-external']['severity'] === 'warning' && str_contains($found['script-external']['message'], 'cdn-js-delivery.example'), '新しい外部ドメインのスクリプトを🟡警告で検知');
check(isset($found['hidden-iframe']), '見えない iframe を検知');
check(count($found) === 4, 'Google アナリティクスなど許可済みのドメインは報告しない');
$m = implode("\n", $n->take());
check(str_contains($m, "投稿 #{$evil}「新着情報」"), '通知に投稿の番号とタイトルを表示する');

section('サイトの URL・管理者');
opt($root, 'home', 'https://evil-redirect.example');
admin($root, 'wp-support');
$app->dbScan(null, $t += 60);
$found = lastFindings($app, $t);
check(isset($found['site-url']) && str_contains((string) $found['site-url']['detail'], 'https://site1.example → https://evil-redirect.example'), 'サイトの URL の書き換えを🔴緊急で検知 (前後の値を表示)');
check(isset($found['db-admin']) && str_contains($found['db-admin']['message'], 'wp-support'), 'DB に直接追加された管理者を🔴緊急で検知 (プラグインを消されていても)');
$root->exec("DELETE FROM site1.wp_usermeta WHERE user_id = (SELECT ID FROM site1.wp_users WHERE user_login = 'admin')");
$app->dbScan(null, $t += 60);
check(isset(lastFindings($app, $t)['db-admin-removed']), '管理者がいなくなったら🟡警告');
$n->take();

section('隔離はできない');
$fid = (int) $found['db-admin']['id'];
try {
    $app->isolateFinding($fid, true);
    check(false, 'DB の検知の隔離を拒否する');
} catch (RuntimeException $e) {
    check(str_contains($e->getMessage(), '管理画面で'), 'DB の検知の隔離を拒否し、管理画面での対応を案内する');
}

section('接続できないとき');
file_put_contents("{$site}/wp-config.php", str_replace("'wp1'", "'nobody'", (string) file_get_contents("{$site}/wp-config.php")));
$app->dbScan(null, $t += 60);
$m = $n->take();
check(count($m) === 1 && str_contains($m[0], 'DB を検査できませんでした') && !str_contains($m[0], PASS), '🟡警告で知らせる (パスワードは表示しない)');
$app->dbScan(null, $t += 60);
check($n->take() === [], '同じエラーは毎回通知しない');
file_put_contents("{$site}/wp-config.php", str_replace("'nobody'", "'wp1'", (string) file_get_contents("{$site}/wp-config.php")));
$r = $app->dbScan(null, $t += 60);
check(isset($r['site1']) && $app->db->siteState(1, 'db_error') === null, '直ったら検査を再開する');

section('二要素認証の解除 (2fa-reset)');
$root->exec("GRANT INSERT, DELETE ON site1.wp_usermeta TO 'wp1'@'%'");
$uid = (int) $root->query("SELECT ID FROM site1.wp_users WHERE user_login = 'wp-support'")->fetchColumn();
foreach (['wpguard_2fa_secret' => 'JBSWY3DPEHPK3PXP', 'wpguard_2fa_last_step' => '123', 'wpguard_2fa_recovery' => 'a:0:{}', 'wpguard_2fa_grace_start' => '1700000000', 'other_meta' => 'keep'] as $k => $v) {
    $root->prepare('INSERT INTO site1.wp_usermeta (user_id, meta_key, meta_value) VALUES (?, ?, ?)')->execute([$uid, $k, $v]);
}
$app->resetTwoFactor('site1', 'wp-support');
$meta = $root->query("SELECT meta_key, meta_value FROM site1.wp_usermeta WHERE user_id = {$uid}")->fetchAll(PDO::FETCH_KEY_PAIR);
check(!isset($meta['wpguard_2fa_secret']) && !isset($meta['wpguard_2fa_recovery']) && !isset($meta['wpguard_2fa_last_step']), '二要素認証の設定を消す');
check(($meta['wpguard_2fa_grace_start'] ?? null) === '1', '猶予期間は終わった扱いにする (次のログインで設定し直し)');
check(($meta['wp_capabilities'] ?? null) !== null && ($meta['other_meta'] ?? null) === 'keep', 'ほかのユーザー情報には触れない');
$m = $n->take();
check(count($m) === 1 && str_contains($m[0], '二要素認証を解除しました') && str_contains($m[0], 'wp-support'), '解除したことを🟡警告で通知する');
try {
    $app->resetTwoFactor('site1', 'nobody');
    check(false, '存在しないユーザー');
} catch (RuntimeException $e) {
    check(str_contains($e->getMessage(), 'ユーザーが見つかりません'), '存在しないユーザーはエラー');
}

exec('rm -rf ' . escapeshellarg($tmp));
echo "\n{$passed} 件成功, {$failed} 件失敗\n";
exit($failed === 0 ? 0 : 1);
