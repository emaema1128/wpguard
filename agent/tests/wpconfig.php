<?php

/*
 * wp-config.php parsing tests (no database needed). Included from tests/run.php.
 */

declare(strict_types=1);

use WPGuard\WpConfigReader;

section('wp-config.php の読み取り (実行せずに)');
$cfg = WpConfigReader::parse(<<<'PHP'
<?php
// define('DB_NAME', 'commented_out');
/* define('DB_USER', 'also_commented'); */
# define('DB_PASSWORD', 'hash_comment');
define( 'DB_NAME', 'real_db' );
define("DB_USER", "real_user");
define('DB_PASSWORD', 'it\'s "secret" \\ ok');
define( 'DB_HOST', 'localhost:/var/run/mysqld/mysqld.sock' );
define('DB_CHARSET', 'utf8mb4');
$note = "define('DB_NAME', 'inside_string')";
$table_prefix = 'wp7_';
if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }
PHP);
check(($cfg['DB_NAME'] ?? null) === 'real_db', 'コメントアウトされた define は無視する');
check(($cfg['DB_USER'] ?? null) === 'real_user', 'ダブルクォートの値');
check(($cfg['DB_PASSWORD'] ?? null) === 'it\'s "secret" \\ ok', 'エスケープを含むパスワード');
check(!in_array('inside_string', $cfg, true), '文字列の中の "define(" に惑わされない');
check(($cfg['$table_prefix'] ?? null) === 'wp7_', 'テーブル接頭辞');
check(!isset($cfg['ABSPATH']), '値が式の定義 (__DIR__ . ...) は読まない');

$c = ['name' => 'db', 'charset' => 'utf8mb4'];
check(WpConfigReader::dsn($c + ['host' => 'localhost']) === 'mysql:dbname=db;charset=utf8mb4;host=localhost', 'DB_HOST: localhost');
check(WpConfigReader::dsn($c + ['host' => '10.0.0.5:3307']) === 'mysql:dbname=db;charset=utf8mb4;host=10.0.0.5;port=3307', 'DB_HOST: ホスト:ポート');
check(WpConfigReader::dsn($c + ['host' => 'localhost:/run/mysqld.sock']) === 'mysql:dbname=db;charset=utf8mb4;unix_socket=/run/mysqld.sock', 'DB_HOST: ソケット');
