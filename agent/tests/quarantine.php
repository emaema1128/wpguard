<?php

/*
 * A-08 quarantine tests. Included from tests/run.php (uses its helpers and $tmp).
 */

declare(strict_types=1);

use WPGuard\App;
use WPGuard\Checksums\NullChecksums;
use WPGuard\Config;
use WPGuard\Logger;

$www3 = "{$tmp}/www3";
$Q = "{$www3}/site-q";
makeWp($Q);
$n3 = new CaptureNotifier();
$app3 = new App(
    Config::fromArray(['roots' => [$www3], 'data_dir' => "{$tmp}/data3", 'log_file' => "{$tmp}/wpguard3.log", 'quarantine_days' => 30]),
    $n3, new Logger("{$tmp}/wpguard3.log"), false, new NullChecksums(),
);
$t3 = time();
$app3->scan(false, null, $t3);
$n3->take();

/** @return string the exception message, or '' when nothing was thrown */
function thrown(callable $fn): string
{
    try {
        $fn();
    } catch (\Throwable $e) {
        return $e->getMessage();
    }
    return '';
}

section('隔離: Web シェルを取り除く');
$shell = "{$Q}/wp-content/uploads/2026/11/shell.php";
file_put_contents($shell, '<?php system($_GET["c"]);');
chmod($shell, 0640);
touch($shell, 1700000000);
$r = $app3->scan(false, null, $t3 += 60);
$fid = $r['site-q']->findings[0]->id;
$m = $n3->take();
check(count($m) === 1 && str_contains($m[0]->text, "wpguard quarantine {$fid}"), '🔴緊急の通知に、隔離のコマンドを表示する');

$q = $app3->isolateFinding($fid, false, $t3 += 60);
check(!file_exists($shell), 'サイトからファイルがなくなる');
$entry = $app3->db->quarantineEntry($q['id']);
check(is_file((string) $entry['stored']) && (fileperms((string) $entry['stored']) & 0777) === 0600, '隔離先に root だけが読める権限で保管する');
check(file_get_contents((string) $entry['stored']) === '<?php system($_GET["c"]);', '中身はそのまま保管する (調査用)');
check((fileperms("{$tmp}/data3/quarantine") & 0077) === 0, '隔離ディレクトリはほかのユーザーから見えない');
$m = $n3->take();
check(count($m) === 1 && str_contains($m[0]->text, 'ファイルを隔離しました') && str_contains($m[0]->text, "wpguard restore {$q['id']}"), '隔離したことを Slack に通知する');
check(array_filter($app3->db->openFindings(), static fn ($f) => (int) $f['id'] === $fid) === [], '検知は「隔離済み」になり、未対応の一覧から消える');
check(str_contains(thrown(fn () => $app3->isolateFinding($fid, false)), "すでに隔離しています (隔離 ID #{$q['id']})"), 'もう一度隔離しようとしたら、隔離済みだと伝える');
$r = $app3->scan(false, null, $t3 += 60);
check(count($r['site-q']->findings) === 0 && count($n3->take()) === 0, '次のスキャンで「削除された」と誤報しない');

section('隔離: 元に戻す');
$app3->restore($q['id'], $t3 += 60);
clearstatcache();
check(is_file($shell) && file_get_contents($shell) === '<?php system($_GET["c"]);', '元の場所に元の中身で戻る');
check((fileperms($shell) & 0777) === 0640 && filemtime($shell) === 1700000000, '権限と更新日時も元に戻る');
check(!is_dir(dirname((string) $entry['stored'])), '隔離先は片付ける');
$m = $n3->take();
check(count($m) === 1 && str_contains($m[0]->text, '元に戻しました'), '元に戻したことを🟡警告で通知する');
sleep(2);
$r = $app3->scan(false, null, $t3 += 60);
check(count($r['site-q']->findings) === 0, '戻したファイルを「新しく作成された」と誤報しない');
check(str_contains(thrown(fn () => $app3->restore($q['id'])), 'すでに元に戻した'), '二度は戻せない');

section('隔離: サイトを壊すファイルは拒否する');
file_put_contents("{$Q}/wp-includes/load.php", "<?php // core\n/* injected */\n");
$r = $app3->scan(false, null, $t3 += 60);
$core = $r['site-q']->findings[0];
$msg = thrown(fn () => $app3->isolateFinding((int) $core->id, false));
check(str_contains($msg, '再インストール') && str_contains($msg, '--force') && is_file("{$Q}/wp-includes/load.php"), 'WordPress 本体のファイルは拒否し、再インストールを案内する');
check(str_contains(thrown(fn () => $app3->isolatePath('site-q', 'wp-content/plugins/hello/hello.php', false)), 'wp plugin install hello --force'), 'プラグインのファイルも拒否し、入れ直しを案内する');
check(str_contains(thrown(fn () => $app3->isolatePath('site-q', 'wp-config.php', false)), '手で取り除いて'), 'wp-config.php は拒否する');
$app3->isolatePath('site-q', 'wp-content/plugins/hello/hello.php', true, $t3 += 60);
check(!file_exists("{$Q}/wp-content/plugins/hello/hello.php"), '--force を付ければ隔離できる');
$n3->take();

section('隔離: 不正なパス');
check(str_contains(thrown(fn () => $app3->isolatePath('site-q', '../../../etc/passwd', false)), 'パスが不正'), '.. でサイトの外を指せない');
mkdir("{$tmp}/outside");
file_put_contents("{$tmp}/outside/victim.txt", 'do not touch');
symlink("{$tmp}/outside", "{$Q}/wp-content/uploads/escape");
check(str_contains(thrown(fn () => $app3->isolatePath('site-q', 'wp-content/uploads/escape/victim.txt', false)), 'サイトの外') && is_file("{$tmp}/outside/victim.txt"), 'リンクしたディレクトリ経由でサイトの外を指せない');
$link = $app3->isolatePath('site-q', 'wp-content/uploads/escape', false, $t3 += 60);
check(!is_link("{$Q}/wp-content/uploads/escape") && is_dir("{$tmp}/outside"), 'シンボリックリンク自体は隔離でき、リンク先には触らない');
$app3->restore($link['id'], $t3 += 60);
check(is_link("{$Q}/wp-content/uploads/escape") && readlink("{$Q}/wp-content/uploads/escape") === "{$tmp}/outside", 'シンボリックリンクも元に戻せる');
check(str_contains(thrown(fn () => $app3->isolatePath('site-q', 'wp-content/uploads/nothing.php', false)), '見つかりません'), '存在しないファイル');
check(str_contains(thrown(fn () => $app3->isolatePath('no-such-site', 'x.php', false)), 'サイトが見つかりません'), '存在しないサイト');
$n3->take();

section('隔離: 保管期間');
file_put_contents("{$Q}/wp-content/uploads/old.php", '<?php // old');
$old = $app3->isolatePath('site-q', 'wp-content/uploads/old.php', false, $t3);
$stored = (string) $app3->db->quarantineEntry($old['id'])['stored'];
$app3->scan(true, null, $t3 + 10 * 86400);
check(is_file($stored), '保管期間 (30 日) 内は残す');
$app3->scan(true, null, $t3 + 31 * 86400);
check(!is_file($stored) && $app3->db->quarantineEntry($old['id'])['purged_at'] !== null, '保管期間を過ぎたら、全件スキャンのときに削除する');
check(str_contains(thrown(fn () => $app3->restore($old['id'])), '削除されています'), '削除済みは戻せない');
