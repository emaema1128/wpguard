<?php

/*
 * WPGuard agent tests. Builds fake WordPress sites in a temp directory and checks
 * what the scanner detects and what would be sent to Slack.
 *
 *   php tests/run.php
 */

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use WPGuard\App;
use WPGuard\Checksums\ChecksumProvider;
use WPGuard\Checksums\NullChecksums;
use WPGuard\Config;
use WPGuard\PatternScanner;
use WPGuard\Logger;
use WPGuard\Notifier\Message;
use WPGuard\Notifier\Notifier;

final class CaptureNotifier implements Notifier
{
    /** @var Message[] */
    public array $sent = [];
    public bool $fail = false;

    public function send(Message $message): bool
    {
        if ($this->fail) {
            return false;
        }
        $this->sent[] = $message;
        return true;
    }

    /** @return Message[] */
    public function take(): array
    {
        $m = $this->sent;
        $this->sent = [];
        return $m;
    }
}

$passed = 0;
$failed = 0;

function check(bool $cond, string $label): void
{
    global $passed, $failed;
    if ($cond) {
        $passed++;
        echo "  ✓ {$label}\n";
    } else {
        $failed++;
        echo "  ✗ {$label}\n";
    }
}

function section(string $title): void
{
    echo "\n{$title}\n";
}

function makeWp(string $dir): void
{
    foreach (['wp-admin', 'wp-includes', 'wp-content/plugins/hello', 'wp-content/themes/twenty', 'wp-content/uploads/2026/11', 'wp-content/cache/page'] as $d) {
        mkdir("{$dir}/{$d}", 0755, true);
    }
    file_put_contents("{$dir}/wp-includes/version.php", "<?php\n\$wp_version = '6.8.3';\n");
    file_put_contents("{$dir}/wp-includes/load.php", "<?php // core\n");
    file_put_contents("{$dir}/wp-admin/admin.php", "<?php // admin\n");
    file_put_contents("{$dir}/wp-config.php", "<?php define('DB_NAME', 'x');\n");
    file_put_contents("{$dir}/wp-load.php", "<?php // load original\n");
    file_put_contents("{$dir}/index.php", "<?php require 'wp-blog-header.php';\n");
    file_put_contents("{$dir}/wp-content/plugins/hello/hello.php", "<?php // hello\n");
    file_put_contents("{$dir}/wp-content/themes/twenty/style.css", "body{}\n");
    file_put_contents("{$dir}/wp-content/uploads/2026/11/photo.jpg", 'JPEGDATA');
    file_put_contents("{$dir}/wp-content/cache/page/index.html", 'cached');
}

/** @param Message[] $messages */
function texts(array $messages): string
{
    return implode("\n=====\n", array_map(static fn (Message $m) => $m->text, $messages));
}

// ---------------------------------------------------------------- setup
$tmp = sys_get_temp_dir() . '/wpguard-test-' . bin2hex(random_bytes(4));
$www = "{$tmp}/www";
mkdir("{$tmp}/data", 0700, true);
makeWp("{$www}/site-a.example.com/public_html");
makeWp("{$www}/site-b");
makeWp("{$www}/site-b/blog");            // WordPress inside another WordPress
mkdir("{$www}/not-wordpress/html", 0755, true);

$config = Config::fromArray([
    'roots' => [$www],
    'data_dir' => "{$tmp}/data",
    'log_file' => "{$tmp}/wpguard.log",
    'aggregate_threshold' => 10,
]);
$notifier = new CaptureNotifier();
$app = new App($config, $notifier, new Logger("{$tmp}/wpguard.log"), false, new NullChecksums());
$A = "{$www}/site-a.example.com/public_html";
$t = time();

// ---------------------------------------------------------------- tests
section('サイトの自動検出');
$sites = $app->discover();
check(array_keys($sites) === ['site-a.example.com', 'site-b', 'site-b/blog'], '3 サイトを検出し、public_html はサイト名から外す: ' . implode(', ', array_keys($sites)));
check($sites['site-b']->wpVersion === '6.8.3', 'WordPress のバージョンを読み取る');

section('初回スキャン = ベースライン作成のみ');
$r = $app->scan(false, null, $t);
check(array_sum(array_map(static fn ($x) => count($x->findings), $r)) === 0, '検知は 0 件');
$m = $notifier->take();
check(count($m) === 3 && str_contains($m[0]->text, '監視を開始しました'), 'サイトごとに「監視を開始しました」を通知');
check($r['site-b']->files === $r['site-b/blog']->files, '入れ子の WordPress は親サイトのスキャンに含めない');
check(!str_contains(implode(',', array_keys($app->db->files($sites['site-a.example.com']->id ?? 1))), 'cache/'), '除外パス (wp-content/cache) は記録しない');

section('変更なし');
sleep(2);
$r = $app->scan(false, null, $t += 60);
check(count($notifier->take()) === 0, '通知なし');
check($r['site-b']->hashed > 0, '記録した直後のファイルは、次のスキャンで 1 回だけ確かめ直す');
$r = $app->scan(false, null, $t += 60);
check($r['site-b']->hashed === 0, 'それ以降の簡易スキャンではハッシュを再計算しない');

section('uploads に PHP を設置される');
file_put_contents("{$A}/wp-content/uploads/2026/11/x.php", '<?php eval(base64_decode($_POST["c"]));');
$r = $app->scan(false, null, $t += 60);
$f = $r['site-a.example.com']->findings;
check(count($f) === 1 && $f[0]->severity->value === 'critical' && $f[0]->rule === 'eval-decode', '🔴緊急 (eval-decode) として検知');
check(str_contains((string) $f[0]->detail, 'eval(base64_decode('), '一致したコードの抜粋を残す');
$m = $notifier->take();
check(count($m) === 1 && str_contains($m[0]->text, '<!channel>') && str_contains($m[0]->text, 'x.php') && str_contains($m[0]->text, '🔍'), '@channel と抜粋付きで Slack に通知');
echo "\n" . preg_replace('/^/m', '      | ', $m[0]->text) . "\n";

section('更新日時を偽装した改ざん (touch -r)');
sleep(1); // ctime is stored in seconds
$mtime = filemtime("{$A}/wp-load.php");
file_put_contents("{$A}/wp-load.php", "<?php // load EVILxxx\n");
touch("{$A}/wp-load.php", $mtime);
clearstatcache();
$r = $app->scan(false, null, $t += 60);
$f = $r['site-a.example.com']->findings;
check(count($f) === 1 && $f[0]->kind === 'modified' && $f[0]->rule === 'core', 'mtime を戻されても ctime の変化で検知');

section('全件スキャン');
$r = $app->scan(true, 'site-b', $t += 60);
check(count($r) === 1 && $r['site-b']->hashed === $r['site-b']->files, '--site で絞り込み、全ファイルを再ハッシュ');
check(count($r['site-b']->findings) === 0, '変更がなければ検知なし');

section('入れ子サイトの変更');
file_put_contents("{$www}/site-b/blog/wp-content/mu-plugins.txt", 'x');
mkdir("{$www}/site-b/blog/wp-content/mu-plugins");
file_put_contents("{$www}/site-b/blog/wp-content/mu-plugins/loader.php", '<?php // backdoor');
$r = $app->scan(false, null, $t += 60);
check(count($r['site-b']->findings) === 0, '親サイト (site-b) では検知しない');
$crit = array_filter($r['site-b/blog']->findings, static fn ($x) => $x->rule === 'mu-plugin');
check(count($crit) === 1, 'site-b/blog で mu-plugins の追加を🔴緊急として検知');
$notifier->take();

section('ファイルの削除・.htaccess・シンボリックリンク');
unlink("{$A}/wp-content/plugins/hello/hello.php");
file_put_contents("{$A}/.htaccess", "RewriteRule .* http://evil.example/ [R]\n");
symlink('/', "{$A}/wp-content/root-link");
$r = $app->scan(false, null, $t += 60);
$byRule = [];
foreach ($r['site-a.example.com']->findings as $x) {
    $byRule[$x->rule] = $x;
}
check(isset($byRule['code']) && $byRule['code']->kind === 'deleted', 'プラグインのファイル削除を検知');
check(isset($byRule['server-config']) && $byRule['server-config']->severity->value === 'critical', '.htaccess の作成を🔴緊急として検知');
check(isset($byRule['symlink']), 'シンボリックリンクを検知');
check($r['site-a.example.com']->files < 50, 'リンク先 (/) はたどらない');
$m = $notifier->take();
check(count($m) === 1 && str_contains($m[0]->text, '2 件の検知') && !str_contains($m[0]->text, 'hello.php'), '通知対象の 2 件を 1 通にまとめる (プラグインの削除は🔵情報なので送らない)');

section('大量の変更はまとめて通知');
for ($i = 0; $i < 25; $i++) {
    file_put_contents("{$A}/wp-content/plugins/hello/file{$i}.php", "<?php // {$i}");
}
$app->scan(false, null, $t += 60);
$m = $notifier->take();
check(count($m) === 1 && str_contains($m[0]->text, '25 件の変更をまとめて') && str_contains($m[0]->text, 'ほか 15 件'), '25 件を要約した 1 通にする');

section('重複通知の抑止');
$evil = file_get_contents("{$A}/wp-content/uploads/2026/11/x.php");
unlink("{$A}/wp-content/uploads/2026/11/x.php");
$app->scan(false, null, $t += 60);
$notifier->take();
file_put_contents("{$A}/wp-content/uploads/2026/11/x.php", $evil);
$r = $app->scan(false, null, $t += 60);
check(count($r['site-a.example.com']->findings) === 1, '再設置は検知として記録する');
check(count($notifier->take()) === 0, '同じ内容は 6 時間以内なら再通知しない');
$r = $app->scan(false, null, $t += 7 * 3600);
file_put_contents("{$A}/wp-content/uploads/2026/11/x.php", $evil . ' ');
$app->scan(false, null, $t += 60);
check(count($notifier->take()) === 1, '内容が変われば通知する');

section('通知に失敗したら、次回また通知する');
file_put_contents("{$A}/wp-content/uploads/2026/11/y.php", '<?php // y');
$notifier->fail = true;
$r = $app->scan(false, null, $t += 60);
$notifier->fail = false;
check(count($notifier->sent) === 0, '失敗時は送信済みにしない');
$app->scan(false, null, $t += 60);
$m = $notifier->take();
check(count($m) === 1 && str_contains($m[0]->text, 'y.php'), '次のスキャンで再送する');
$app->scan(false, null, $t += 60);
check(count($notifier->take()) === 0, '再送できたら、それ以降は送らない');

section('Slack の書式を悪用したファイル名');
file_put_contents("{$A}/wp-content/uploads/2026/11/<!here>`x`.php", '<?php');
$app->scan(false, null, $t += 60);
$m = $notifier->take();
check(count($m) === 1 && !str_contains($m[0]->text, '<!here>') && str_contains($m[0]->text, '&lt;!here&gt;'), 'ファイル名の <!here> を無害化する');

section('画像のアップロードは通知しない');
file_put_contents("{$A}/wp-content/uploads/2026/11/new.png", 'PNG');
$r = $app->scan(false, null, $t += 60);
check(count($r['site-a.example.com']->findings) === 1 && $r['site-a.example.com']->findings[0]->severity->value === 'info', '🔵情報として記録だけする');
check(count($notifier->take()) === 0, '通知なし');

section('検知の確認 (ack)');
$open = $app->db->openFindings();
check(count($open) > 0 && $open[0]['severity'] === 'critical', '未対応の一覧は緊急が先頭');
$n = $app->db->ackFindings([(int) $open[0]['id']], $t);
check($n === 1 && count($app->db->openFindings()) === count($open) - 1, 'ID 指定で確認済みにする');
$app->db->ackAllFindings(null, $t);
check(count($app->db->openFindings()) === 0, '--all で全件確認済みにする');

section('ベースラインの作り直し');
$r = $app->rebaseline('site-a.example.com', $t += 60);
$m = $notifier->take();
check($r['site-a.example.com']->baseline && count($m) === 1 && str_contains($m[0]->text, 'ベースラインを作り直しました'), '現在の状態を正常として記録し直す');

section('サイトが消えた / 戻った');
rename("{$www}/site-b/blog", "{$tmp}/blog-moved");
$app->scan(false, null, $t += 60);
$m = $notifier->take();
check(count($m) === 1 && str_contains($m[0]->text, 'サイトが見つからなくなりました'), '消えたサイトを🟡警告で通知');
$app->scan(false, null, $t += 60);
check(count($notifier->take()) === 0, '2 回目以降は通知しない');
rename("{$tmp}/blog-moved", "{$www}/site-b/blog");
$app->scan(false, null, $t += 60);
$m = $notifier->take();
check(count($m) === 1 && str_contains($m[0]->text, '再び見つかりました'), '戻ったら通知する');

require __DIR__ . '/step2.php';
require __DIR__ . '/quarantine.php';

// ---------------------------------------------------------------- cleanup
exec('rm -rf ' . escapeshellarg($tmp));
echo "\n{$passed} 件成功, {$failed} 件失敗\n";
exit($failed === 0 ? 0 : 1);
