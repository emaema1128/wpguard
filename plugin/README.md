# WPGuard Sentinel (各サイト用プラグイン)

各 WordPress サイトの中で動き、ログイン攻撃を防ぎ、管理者の追加などを Slack にすぐ通知します。
ファイルの監視はサーバー側の監視エージェント (`../agent`) が担当します。

mu-plugin (必ず使うプラグイン) として入れるので、管理画面から無効化できません。

## 機能

| ID | 機能 | 内容 |
|---|---|---|
| P-01 | ログイン試行の制限 | 15 分以内に 5 回失敗した IP を 15 分ロック。ロック中は正しいパスワードでも入れない。ロックしたら試されたユーザー名と一緒に 🟡警告 |
| | 管理者の新しい IP | 管理者が、これまでに使ったことのない IP からログインしたら 🟡警告 |
| | ユーザー名を探らせない | 「ユーザーが存在しない」と「パスワードが違う」を同じメッセージにする |
| P-02 | 管理者の監視 | 管理者の作成・昇格を 🔴緊急。DB を直接書き換えて追加された管理者も、5 分おきの点検で 🔴緊急 |
| P-03 | プラグイン/テーマの監視 | 有効化・インストール・テーマ変更を 🟡警告。ログインしていない状態での有効化 (マルウェアの典型) は 🔴緊急 |
| P-04 | ファイル編集の禁止 | 管理画面のプラグイン/テーマ編集機能を無効にする |
| P-05 | XML-RPC・ユーザー列挙 | `xmlrpc.php` を 403 にする。REST API のユーザー一覧、`?author=1`、ユーザーのサイトマップ、oEmbed の投稿者名を隠す |
| P-06 | uploads での PHP 実行禁止 | `uploads/.htaccess` を作る。消されたら作り直して 🟡警告 |
| P-07 | 二要素認証 | 管理者はログインのたびに、認証アプリの 6 桁のコードが必要。導入から 7 日間は猶予 (管理画面にお知らせ)。予備コード 10 個。コードの総当たりは P-01 のロックで防ぐ。二要素認証を使う人はアプリケーションパスワードを使えない (抜け道になるため) |
| P-08 | WP-Cron の監視 | 新しい定期実行の処理を 5 分おきに点検。処理のコードの場所で判定する: プラグイン・テーマ・本体なら記録だけ、mu-plugins や処理が見つからないものは 🟡警告、uploads・`eval` で作られたコード・それ以外の場所は 🔴緊急。怪しい引数 (URL、`base64_decode` など) やランダムな名前も 🔴緊急 |

Slack への送信は、ページを表示し終わってから行います。送れなかった通知は保存して、5 分おきに再送します。

## 動作環境

- WordPress 5.9 以上、PHP 7.4 以上
- Apache (P-06 の `.htaccess` のため。Apache 本体の設定でも禁止しておくことを推奨。ルートの README を参照)

## インストール

### 1. 共通設定を作る (全サイトで 1 回だけ)

```bash
sudo mkdir -p /etc/wpguard
sudo cp sentinel.example.php /etc/wpguard/sentinel.php
sudo chown root:root /etc/wpguard/sentinel.php
sudo chmod 644 /etc/wpguard/sentinel.php
sudo vi /etc/wpguard/sentinel.php     # WPGUARD_SLACK_WEBHOOK を設定
```

PHP の `open_basedir` で `/etc` が読めないサイトは、そのサイトの `wp-config.php` で定数を直接定義してください。

```php
define('WPGUARD_SLACK_WEBHOOK', 'https://hooks.slack.com/services/...');
```

### 2. 全サイトに配置する

```bash
sudo ./install.sh --dry-run /var/www   # 対象のサイトを確認
sudo ./install.sh /var/www
```

更新するときも同じコマンドです。プラグインのファイルは root 所有になり、Web サーバーのユーザーからは書き換えられません。

**監視エージェントの通知について**: 配置すると、監視エージェントが「mu-plugins 内のファイルが作成されました」「uploads/.htaccess が作成されました」を 🔴緊急で通知します。自分たちの作業なので、確認したら `wpguard ack --site=<サイト> --all` で確認済みにしてください。

## 二要素認証の運用

**導入したとき**: 管理者は 7 日以内に設定してください。管理画面の上にお知らせが出るので、「今すぐ設定する」から設定できます (メニューの「ユーザー」→「二要素認証」)。7 日を過ぎると、ログイン画面で設定しないと入れなくなります。

**設定のしかた**: スマホに認証アプリ (Google Authenticator、Microsoft Authenticator、1Password など) を入れ、画面に表示される設定キーを入力します。アプリに表示された 6 桁のコードを入れれば完了です。最後に表示される**予備コード 10 個を、必ず安全な場所に保存してください**。

**スマホをなくしたとき**: 確認コードの代わりに予備コード (`xxxx-xxxx`) でログインできます。各コードは 1 回だけ使えます。ログインしたら、「二要素認証」の画面で予備コードを作り直してください。予備コードを使うと Slack に 🟡警告が届きます。

**予備コードもなくしたとき**: サーバーで解除します。次回のログイン時に、ログイン画面で設定し直してもらいます。

```bash
sudo wpguard 2fa-reset --site=example.com --user=tanaka
```

QR コードは表示しません (設定キーの入力か、スマホでリンクをタップして登録します)。

## サイトごとの設定

サイトの `wp-config.php` で定義した定数は、共通設定より優先されます。

| 定数 | 既定値 | 内容 |
|---|---|---|
| `WPGUARD_SLACK_WEBHOOK` | `''` | Slack の Incoming Webhook URL |
| `WPGUARD_SITE_NAME` | サイトのドメイン | 通知に表示する名前 |
| `WPGUARD_SLACK_MENTION` | `'<!channel>'` | 🔴緊急に付けるメンション |
| `WPGUARD_NOTIFY_INFO` | `false` | 🔵情報 (更新・無効化など) も通知する |
| `WPGUARD_TIMEZONE` | `'Asia/Tokyo'` | 通知の時刻 |
| `WPGUARD_LOGIN_MAX_RETRIES` | `5` | ロックするまでの失敗回数 |
| `WPGUARD_LOGIN_WINDOW` | `900` | 失敗を数える期間 (秒) |
| `WPGUARD_LOGIN_LOCKOUT` | `900` | ロックする時間 (秒) |
| `WPGUARD_TRUSTED_PROXIES` | `[]` | Cloudflare などのプロキシの IP。ここからの接続だけ `X-Forwarded-For` を信じる |
| `WPGUARD_ALLOW_XMLRPC` | `false` | **Jetpack や WordPress アプリを使うサイトは `true` に** |
| `WPGUARD_ALLOW_FILE_EDIT` | `false` | 管理画面でのファイル編集を許可する |
| `WPGUARD_2FA` | `true` | 二要素認証を使う |
| `WPGUARD_2FA_ROLES` | `['administrator']` | 二要素認証を必須にする権限グループ |
| `WPGUARD_2FA_GRACE_DAYS` | `7` | 必須になるまでの猶予 (日) |
| `WPGUARD_2FA_ALLOW_APP_PASSWORDS` | `false` | 二要素認証を使う人にアプリケーションパスワードを許可する (外部連携で必要なサイトだけ) |
| `WPGUARD_SHARED_CONFIG` | `'/etc/wpguard/sentinel.php'` | 共通設定のパス |

**Cloudflare などを使っている場合**: `WPGUARD_TRUSTED_PROXIES` を設定しないと、全員がプロキシの IP からアクセスしているように見えます。その結果、誰かが 5 回間違えると全員がロックされます。

## 注意

- Webhook URL は Web サーバーが読める場所に置くため、サイトを乗っ取られると読まれる可能性があります。漏れたら Slack で Webhook を作り直してください。
- ログイン制限の記録には WordPress の transient を使います。オブジェクトキャッシュ (Redis など) を使っていても動きます。

## テスト

本物の WordPress を組み立てて、通しで試します。初回は `downloads.wordpress.org` からダウンロードします。

```bash
php tests/e2e.php                                     # PHP の内蔵サーバー + SQLite (手軽)
WPGUARD_E2E_IMAGE=php:7.4-apache php tests/e2e.php    # Docker の Apache + PHP 7.4 + MariaDB (本番に近い)
WPGUARD_E2E_IMAGE=php:8.3-apache php tests/e2e.php
```

Docker で動かすと、uploads の PHP が Apache で実際に実行されないことも確かめます。

P-08 は、人気のプラグイン 10 個 (WooCommerce、Jetpack、Yoast SEO、Elementor、Wordfence、UpdraftPlus など) を有効化して、誤報が出ないことを確認しています。

確認済み: PHP 8.4 (内蔵サーバー) / Apache 2.4.54 + PHP 7.4.33 + MariaDB 11.8 / Apache 2.4.71 + PHP 8.3.37 + MariaDB 11.8
