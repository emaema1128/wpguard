<?php

/*
 * Recognizing WPGuard Sentinel's own files (installed with plugin/install.sh).
 * Included from tests/run.php (uses its helpers and $tmp).
 */

declare(strict_types=1);

use WPGuard\App;
use WPGuard\Checksums\NullChecksums;
use WPGuard\Config;
use WPGuard\Logger;

$www5 = "{$tmp}/www5";
$P = "{$www5}/site-p";
makeWp($P);
$pluginSrc = dirname(__DIR__, 2) . '/plugin';
$manifest = "{$tmp}/sentinel.sha256";

/** Copies the plugin into the site and writes the manifest, as plugin/install.sh does. */
$deploy = static function () use ($P, $pluginSrc, $manifest): void {
    exec('cp -R ' . escapeshellarg("{$pluginSrc}/wpguard-sentinel") . ' ' . escapeshellarg("{$P}/wp-content/mu-plugins/")
        . ' && cp ' . escapeshellarg("{$pluginSrc}/wpguard-sentinel.php") . ' ' . escapeshellarg("{$P}/wp-content/mu-plugins/"));
    exec('cd ' . escapeshellarg($pluginSrc) . ' && find wpguard-sentinel wpguard-sentinel.php -type f -print0 | sort -z | xargs -0 sha256sum > ' . escapeshellarg($manifest));
};
@mkdir("{$P}/wp-content/mu-plugins");
$n5 = new CaptureNotifier();
$app5 = new App(
    Config::fromArray(['roots' => [$www5], 'data_dir' => "{$tmp}/data5", 'db_scan' => false, 'log_file' => "{$tmp}/wpguard5.log", 'sentinel_manifest' => $manifest]),
    $n5, new Logger("{$tmp}/wpguard5.log"), false, new NullChecksums(),
);
$t5 = time();
$app5->scan(false, null, $t5);
$n5->take();

section('WPGuard Sentinel 自身のファイル');
$deploy();
$ht = "{$P}/wp-content/uploads/.htaccess";
// What WordPress writes with insert_with_markers() on a Japanese site.
file_put_contents($ht, "# BEGIN WPGuard\n# \"BEGIN WPGuard\" から \"END WPGuard\" までのディレクティブ (行) は\n# 動的に生成され、WordPress フィルターによってのみ修正が可能です。\n# uploads 内では PHP を実行しない\n<FilesMatch \"\\.(?i:php[0-9]?|phtml|pht|phar|phps|inc)$\">\n    Require all denied\n</FilesMatch>\n# END WPGuard\n");
$r = $app5->scan(false, null, $t5 += 60);
$rules = array_count_values(array_map(static fn ($f) => $f->rule, $r['site-p']->findings));
check(($rules['sentinel'] ?? 0) === count($r['site-p']->findings) && count($r['site-p']->findings) > 10, 'plugin/install.sh で入れたファイルと uploads/.htaccess は、正規のものとして記録だけする');
check(count($n5->take()) === 0, '導入しても緊急の通知は出ない');

$deploy();
$r = $app5->scan(false, null, $t5 += 60);
check(count($n5->take()) === 0, '入れ直し (更新) でも通知は出ない');

sleep(2);
$target = "{$P}/wp-content/mu-plugins/wpguard-sentinel/src/LoginGuard.php";
$original = file_get_contents($target);
file_put_contents($target, str_replace('return new \\WP_Error(\'wpguard_locked\'', 'return $user; new \\WP_Error(\'wpguard_locked\'', $original));
file_put_contents("{$P}/wp-content/mu-plugins/wpguard-sentinel/src/Updater.php", '<?php // dropped');
$r = $app5->scan(false, null, $t5 += 60);
$byRule = [];
foreach ($r['site-p']->findings as $f) {
    $byRule[$f->rule] = $f;
}
check(isset($byRule['sentinel-modified']) && $byRule['sentinel-modified']->severity->value === 'critical', 'WPGuard のファイルが書き換えられたら🔴緊急 (ログイン制限を無効にする改ざんなど)');
check(isset($byRule['sentinel-extra']) && $byRule['sentinel-extra']->severity->value === 'critical', 'WPGuard のディレクトリに紛れ込んだファイルは🔴緊急');
$m = $n5->take();
check(count($m) === 1 && str_contains($m[0]->text, '改ざんされています'), 'Slack に通知する');

section('元に戻ったら、古い検知を自動で片付ける');
$modifiedId = $byRule['sentinel-modified']->id;
sleep(2);
file_put_contents($target, $original);
$app5->scan(false, null, $t5 += 60);
$open = array_map(static fn ($f) => (int) $f['id'], $app5->db->openFindings());
check(!in_array($modifiedId, $open, true), '正規の内容に戻ったファイルの検知は「確認済み」になる');
check(count(array_filter($app5->db->openFindings(), static fn ($f) => $f['rule'] === 'sentinel-extra')) === 1, '紛れ込んだファイルの検知はそのまま残る');
$n5->take();

section('uploads/.htaccess の見分け');
sleep(2);
file_put_contents($ht, file_get_contents($ht) . "AddHandler application/x-httpd-php .jpg\n");
$r = $app5->scan(false, null, $t5 += 60);
$f = $r['site-p']->findings[0] ?? null;
check($f !== null && $f->severity->value === 'critical' && $f->rule !== 'sentinel', 'WPGuard の設定に何か書き足されたら🔴緊急');
$n5->take();

section('一覧がないとき (plugin/install.sh を使わずに入れた場合)');
unlink($manifest);
$app6 = new App(
    Config::fromArray(['roots' => [$www5], 'data_dir' => "{$tmp}/data5", 'db_scan' => false, 'log_file' => "{$tmp}/wpguard5.log", 'sentinel_manifest' => $manifest]),
    $n5, new Logger("{$tmp}/wpguard5.log"), false, new NullChecksums(),
);
file_put_contents("{$P}/wp-content/mu-plugins/wpguard-sentinel/src/Extra2.php", '<?php // x');
$r = $app6->scan(false, null, $t5 += 60);
check(($r['site-p']->findings[0] ?? null)?->rule === 'mu-plugin', '従来どおり mu-plugins の変更として🔴緊急');
