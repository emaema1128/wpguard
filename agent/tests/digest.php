<?php

/*
 * N-04 daily digest tests. Included from tests/run.php (uses its helpers and $tmp).
 */

declare(strict_types=1);

use WPGuard\App;
use WPGuard\Checksums\NullChecksums;
use WPGuard\Config;
use WPGuard\Logger;

$www4 = "{$tmp}/www4";
makeWp("{$www4}/alpha");
makeWp("{$www4}/beta");
makeWp("{$www4}/gamma");
$n4 = new CaptureNotifier();
$app4 = new App(
    Config::fromArray(['roots' => [$www4], 'data_dir' => "{$tmp}/data4", 'db_scan' => false, 'log_file' => "{$tmp}/wpguard4.log", 'stale_hours' => 3]),
    $n4, new Logger("{$tmp}/wpguard4.log"), false, new NullChecksums(),
);
$t4 = time();
$app4->scan(false, null, $t4);
$n4->take();

section('日次サマリー: 異常なし');
$app4->digest($t4 + 600);
$m = $n4->take();
check(count($m) === 1 && str_contains($m[0]->text, '✅') && str_contains($m[0]->text, '監視中 3 サイト') && str_contains($m[0]->text, '異常はありません'), '全サイト正常なら「✅ 異常はありません」の短い 1 通');
check($m[0]->severity->value === 'info' && !str_contains($m[0]->text, '<!channel>'), '異常がなければメンションしない');
echo "\n" . preg_replace('/^/m', '      | ', $m[0]->text) . "\n";

section('日次サマリー: 問題のあるサイトだけ並べる');
file_put_contents("{$www4}/beta/wp-content/uploads/2026/11/x.php", '<?php eval(base64_decode("eA=="));');
file_put_contents("{$www4}/gamma/wp-content/plugins/hello/hello.php", "<?php // changed\n");
$app4->scan(false, null, $t4 += 60);
$n4->take();
$app4->digest($t4 + 600);
$m = $n4->take();
$text = $m[0]->text ?? '';
check(str_contains($text, '🔴 *[日次サマリー]') && $m[0]->severity->value === 'critical', '未対応の🔴緊急があれば、見出しを🔴にする');
check(str_contains($text, '*beta*: 未対応 🔴1') && str_contains($text, '*gamma*: 未対応 🟡1'), '問題のあるサイトと件数を並べる');
check(strpos($text, '*beta*') < strpos($text, '*gamma*'), '🔴緊急のあるサイトを先に並べる');
check(!str_contains($text, '*alpha*') && str_contains($text, '異常のないサイト: 1'), '正常なサイトは数だけ');
check(str_contains($text, 'wpguard findings'), '一覧のコマンドを案内する');
echo "\n" . preg_replace('/^/m', '      | ', $text) . "\n";

section('日次サマリー: 止まっているスキャン・消えたサイト');
$app4->db->ackAllFindings(null, $t4);
$app4->scan(false, 'alpha', $t4 + 5 * 3600);
$n4->take();
$app4->digest($t4 + 5 * 3600 + 60);
$text = $n4->take()[0]->text ?? '';
check(str_contains($text, '*beta*: ⚠️ 最後のスキャンが 5 時間前') && str_contains($text, '*gamma*: ⚠️') && !str_contains($text, '*alpha*'), '3 時間以上スキャンされていないサイトを知らせる (cron の停止に気づける)');
rename("{$www4}/gamma", "{$tmp}/gamma-moved");
$app4->scan(false, null, $t4 + 6 * 3600);
$n4->take();
$app4->digest($t4 + 6 * 3600 + 60);
$text = $n4->take()[0]->text ?? '';
check(str_contains($text, '*gamma*: ⚠️') && str_contains($text, '見つかりません') && str_contains($text, '監視中 2 サイト'), '見つからなくなったサイトを知らせ、監視中の数から外す');

section('日次サマリー: 対応済みの検知だけなら「異常なし」');
rename("{$tmp}/gamma-moved", "{$www4}/gamma");
$app4->scan(false, null, $t4 + 6 * 3600 + 120);
$app4->db->ackAllFindings(null, $t4);
$n4->take();
$app4->digest($t4 + 6 * 3600 + 180);
$text = $n4->take()[0]->text ?? '';
check(str_contains($text, '✅') && str_contains($text, '異常はありません') && str_contains($text, '過去 24 時間: 検知 🔴1 🟡1'), '検知をすべて確認済みにしたら ✅ (24 時間の件数は合計の行にだけ出す)');
echo "\n" . preg_replace('/^/m', '      | ', $text) . "\n";

section('日次サマリー: 送信失敗');
$n4->fail = true;
check($app4->digest($t4 + 7 * 3600) === false, '送れなかったら失敗を返す (cron のログに残る)');
$n4->fail = false;
