<?php

/*
 * WPGuard 設定ファイル
 *
 * このファイルを config.php としてコピーし、root だけが読めるようにしてください。
 *   cp config.example.php config.php
 *   chown root:root config.php && chmod 600 config.php
 *
 * 省略した項目には既定値が使われます。
 */

return [
    // WordPress を探すディレクトリ。この下にある WordPress を自動で監視対象にします。
    'roots' => ['/var/www'],

    // roots から何階層下まで探すか (例: /var/www/example.com/public_html は 2 階層)
    'discovery_max_depth' => 4,

    // 通知に表示するサイト名を変えたいときに指定します (省略するとディレクトリ名から自動で決めます)
    'site_names' => [
        // '/var/www/example.com/public_html' => 'example.com',
    ],

    // 状態データ (ハッシュ DB など) とログの保存先。Web サーバーのユーザーから書き込めない場所にしてください。
    'data_dir' => '/var/lib/wpguard',
    'log_file' => '/var/log/wpguard/wpguard.log',

    'timezone' => 'Asia/Tokyo',

    // 監視しないパス (サイトのルートからの相対パス、ワイルドカード可)。
    // ここに入れた場所にマルウェアを置かれても検知できないので、必要最小限にしてください。
    'exclude' => [
        'wp-content/cache/*',
    ],

    // これより大きいファイルはハッシュを計算せず、サイズと日時だけで変更を判定します
    'max_hash_bytes' => 100 * 1024 * 1024,

    // 怪しいコードを探すとき、1 ファイルの先頭から読む最大サイズ
    'max_scan_bytes' => 5 * 1024 * 1024,

    // 検出ルールのファイル (省略すると rules/patterns.php)
    // 'rules_file' => '/opt/wpguard/rules/patterns.php',

    // WordPress.org の公式チェックサムと照合する (api.wordpress.org と downloads.wordpress.org への通信が必要)
    'checksums' => true,
    'checksum_timeout' => 10,

    // Slack に通知する最低の重要度: critical / warning / info
    'notify_min_severity' => 'warning',

    // 同じ検知を再通知しない時間
    'dedupe_hours' => 6,

    // 1 サイトでこの件数を超えたら、1 通にまとめて通知します (プラグイン更新時など)
    'aggregate_threshold' => 10,

    // 隔離したファイルを保管する日数 (過ぎたら全件スキャンのときに削除します)
    'quarantine_days' => 30,

    // 日次サマリーで「スキャンが止まっている」と知らせるまでの時間
    'stale_hours' => 3,

    // WPGuard Sentinel (サイト用プラグイン) の正規のファイルの一覧 (plugin/install.sh が作る)
    // mu-plugins の WPGuard のファイルがこれと一致すれば通知せず、違えば改ざんとして通知します
    'sentinel_manifest' => '/etc/wpguard/sentinel.sha256',

    // 日次サマリーに、ModSecurity (WAF) が遮断した件数を載せる (docs/modsecurity.md)
    // ModSecurity が有効なときだけ表示します
    'waf_digest' => true,
    'waf_logs' => ['/var/log/apache2/error.log', '/var/log/apache2/error.log.1'],

    // 各サイトの DB を検査する (全件スキャンのとき。読み取りだけで、書き換えはしません)
    'db_scan' => true,
    'db_timeout' => 5,

    // 投稿や設定に埋め込まれていても通知しない、外部スクリプトの読み込み元
    // (サブドメインも含む。サイト自身のドメインは自動で許可)
    // 'db_script_allow' => ['googletagmanager.com', 'google-analytics.com', ...],

    'slack' => [
        // Slack の Incoming Webhook URL
        'webhook_url' => '',

        // 重要度ごとに別のチャンネルへ送りたいときに指定します (省略すると webhook_url に送ります)
        'webhooks' => [
            // 'critical' => 'https://hooks.slack.com/services/...',
        ],

        // 緊急の通知に付けるメンション ('' で無効)
        'mention_critical' => '<!channel>',

        'timeout' => 10,
    ],
];
