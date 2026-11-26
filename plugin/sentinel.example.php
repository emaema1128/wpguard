<?php
/*
 * WPGuard Sentinel の共通設定 (全サイト共通)
 *
 * /etc/wpguard/sentinel.php に置くと、すべてのサイトがこの設定を使います。
 *   sudo mkdir -p /etc/wpguard
 *   sudo cp sentinel.example.php /etc/wpguard/sentinel.php
 *   sudo chown root:root /etc/wpguard/sentinel.php && sudo chmod 644 /etc/wpguard/sentinel.php
 *
 * サイトごとに変えたい項目は、そのサイトの wp-config.php で同じ名前の定数を定義してください (そちらが優先されます)。
 * 注意: Web サーバー (www-data) が読めるファイルなので、サイトを乗っ取られると Webhook URL は読まれます。
 *       漏れたら Slack で Webhook を作り直してください。
 */

$wpguard_defaults = [
    // Slack の Incoming Webhook URL
    'WPGUARD_SLACK_WEBHOOK' => '',

    // 緊急の通知に付けるメンション ('' で無効)
    'WPGUARD_SLACK_MENTION' => '<!channel>',

    // 🔵情報 (プラグインの更新・無効化など) も通知するか
    'WPGUARD_NOTIFY_INFO' => false,

    'WPGUARD_TIMEZONE' => 'Asia/Tokyo',

    // ログイン制限: WINDOW 秒の間に MAX_RETRIES 回失敗したら、その IP を LOCKOUT 秒ロック
    'WPGUARD_LOGIN_MAX_RETRIES' => 5,
    'WPGUARD_LOGIN_WINDOW' => 900,
    'WPGUARD_LOGIN_LOCKOUT' => 900,

    // Cloudflare やロードバランサーの後ろにある場合、その IP アドレス (X-Forwarded-For を信頼する接続元)
    'WPGUARD_TRUSTED_PROXIES' => [],

    // Jetpack など XML-RPC が必要なサイトでは、そのサイトの wp-config.php で true にしてください
    'WPGUARD_ALLOW_XMLRPC' => false,

    // 管理画面でのファイル編集を許可するか
    'WPGUARD_ALLOW_FILE_EDIT' => false,

    // 二要素認証 (認証アプリの 6 桁のコード)
    'WPGUARD_2FA' => true,
    // 必須にする権限グループ (それ以外のユーザーも、自分で設定すれば使えます)
    'WPGUARD_2FA_ROLES' => ['administrator'],
    // 導入してから必須になるまでの猶予 (日)。0 にすると、すぐに必須になります
    'WPGUARD_2FA_GRACE_DAYS' => 7,
    // 二要素認証を使う人のアプリケーションパスワード (REST API 用の別のパスワード) を許可するか
    // 許可すると、それだけで二要素認証なしに REST API を使えます。外部サービスとの連携で必要なサイトだけ true に
    'WPGUARD_2FA_ALLOW_APP_PASSWORDS' => false,
];

foreach ($wpguard_defaults as $wpguard_name => $wpguard_value) {
    if (!defined($wpguard_name)) {
        define($wpguard_name, $wpguard_value);
    }
}
unset($wpguard_defaults, $wpguard_name, $wpguard_value);
