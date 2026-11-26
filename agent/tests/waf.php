<?php

/*
 * ModSecurity summary in the daily digest. Uses lines from a real Apache error log
 * (tests/fixtures/modsec-error.log: 3 blocked requests from ModSecurity 2.9.11 + CRS 3.3.7).
 * Included from tests/run.php.
 */

declare(strict_types=1);

use WPGuard\Config;
use WPGuard\Digest;
use WPGuard\WafLog;

$fixture = (string) file_get_contents(__DIR__ . '/fixtures/modsec-error.log');
$utc = new DateTimeZone('UTC');
$at = (new DateTimeImmutable('2026-11-26 02:47:30', $utc))->getTimestamp();

// More traffic built from the real lines: another site, another client, and an old block.
$shop = str_replace(['[hostname "127.0.0.1"]', '[client 127.0.0.1:', 'unique_id "'], ['[hostname "shop.example"]', '[client 203.0.113.5:', 'unique_id "S'], $fixture);
$shop2 = str_replace('unique_id "S', 'unique_id "T', $shop);
$old = str_replace(['2026]', 'unique_id "'], ['2025]', 'unique_id "O'], $fixture);
$log = "{$tmp}/apache-error.log";
file_put_contents($log, $old . $fixture . $shop . $shop2);
file_put_contents("{$log}.1", "[Wed Nov 25 23:00:00.000000 2026] [mpm_prefork:notice] [pid 1] AH00163: Apache configured\n");

section('WAF: Apache のエラーログから集計');
$s = (new WafLog([$log, "{$log}.1", "{$tmp}/no-such.log"], $utc))->summarize($at - 3600, $at + 3600);
check($s !== null && $s['mode'] === 'block' && $s['blocked'] === 9, '遮断の件数を数える (24 時間より前は数えない): ' . ($s['blocked'] ?? '?'));
check(($s['hosts'] ?? []) === ['shop.example' => 6, '127.0.0.1' => 3], 'サイトごとの件数 (多い順)');
check(array_key_first($s['clients'] ?? []) === '203.0.113.5' && ($s['clients']['203.0.113.5'] ?? 0) === 6, '接続元ごとの件数 (ポート番号は除く)');
check(($s['reasons']['SQL インジェクション'] ?? 0) === 6 && isset($s['reasons']['外部ファイルの読み込み']), '理由のルールから攻撃の種類を数える');
check(!isset($s['reasons']['不正な形式のリクエスト']), '「Host が IP アドレス」の注意 (920350) は理由に数えない');

$detect = str_replace('ModSecurity: Access denied with code 403 (phase 2).', 'ModSecurity: Warning.', $fixture);
file_put_contents("{$tmp}/detect.log", $detect);
$d = (new WafLog(["{$tmp}/detect.log"], $utc))->summarize($at - 3600, $at + 3600);
check(($d['mode'] ?? '') === 'detect' && ($d['blocked'] ?? 0) === 3, '記録だけのモード (DetectionOnly) を見分け、遮断されるはずだった件数を数える');
check((new WafLog(["{$tmp}/no-such.log"], $utc))->summarize(0, $at) === null, 'ログを読めなければ何も返さない');

$tokyo = (new WafLog([$log], new DateTimeZone('Asia/Tokyo')))->summarize($at - 3600, $at + 3600);
check(($tokyo['blocked'] ?? -1) === 0, 'サーバーのタイムゾーンで時刻を読む (違うタイムゾーンなら範囲から外れる)');

section('WAF: 日次サマリー');
makeWp("{$tmp}/www7/clean");
$app7 = new WPGuard\App(
    Config::fromArray(['roots' => ["{$tmp}/www7"], 'data_dir' => "{$tmp}/data7", 'db_scan' => false, 'log_file' => "{$tmp}/wpguard7.log", 'waf_module_file' => $log]),
    new CaptureNotifier(), new WPGuard\Logger("{$tmp}/wpguard7.log"), false, new WPGuard\Checksums\NullChecksums(),
);
$app7->scan(false, null, $at);
$text = (new Digest($app7->db, $app7->config, new WafLog([$log], $utc)))->build($at + 60)->text;
check(str_contains($text, '🛡 *WAF (24 時間)*: 遮断 9 件') && str_contains($text, 'サイト: shop.example 6 件 / 127.0.0.1 3 件') && str_contains($text, '多い接続元: 203.0.113.5 6 件'), '遮断の件数・サイト・接続元を載せる');
check(str_contains($text, '主な種類: SQL インジェクション 6 件'), '攻撃の種類を載せる');
check(str_contains($text, '✅') && !str_contains($text, '確認が必要'), 'WAF の遮断があっても、サイトの状態は「異常なし」のまま (遮断できているので)');
echo "\n" . preg_replace('/^/m', '      | ', $text) . "\n";

$text = (new Digest($app7->db, $app7->config, new WafLog(["{$tmp}/detect.log"], $utc)))->build($at + 60)->text;
check(str_contains($text, '記録だけのモード') && str_contains($text, '遮断されるはずだったもの 3 件') && str_contains($text, '多い URL: /'), '記録だけのモードでは、確認を促し、URL も載せる');

$noModule = Config::fromArray(['roots' => ["{$tmp}/www7"], 'data_dir' => "{$tmp}/data7", 'log_file' => "{$tmp}/wpguard7.log", 'waf_module_file' => "{$tmp}/no-such.load"]);
file_put_contents("{$tmp}/plain.log", "[Thu Nov 26 02:47:05.622831 2026] [core:notice] [pid 1] AH00094: Command line: '/usr/sbin/apache2'\n");
$text = (new Digest($app7->db, $noModule, new WafLog(["{$tmp}/plain.log"], $utc)))->build($at + 60)->text;
check(!str_contains($text, 'WAF'), 'ModSecurity が入っていなければ、WAF の段落を出さない (「遮断 0 件」で誤解させない)');
