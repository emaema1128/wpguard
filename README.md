# WPGuard

VPS 上の複数の WordPress サイトを監視し、マルウェアの設置や改ざんを Slack に通知するツールです。

- `agent/` … 監視エージェント (サーバー側で cron 実行)。ファイルの改ざんとマルウェアを検知する
- `plugin/` … 各サイトに入れるプラグイン (mu-plugin)。ログイン保護・管理者の監視・防御設定。詳しくは [plugin/README.md](plugin/README.md)

**サーバーに導入するときは [docs/deploy.md](docs/deploy.md) の手順で進めてください。** 以下は監視エージェントの詳しい説明です。

## 監視エージェントでできること

| 機能 | 内容 |
|---|---|
| サイトの自動検出 | `roots` の下にある WordPress を自動で見つける。サイトを追加すれば次回から監視対象になる |
| 改ざん検知 | ファイルの追加・変更・削除を検知する。`touch` で更新日時を戻されても ctime で見抜く |
| 怪しいコードの検出 | `eval(base64_decode(...))`、Web シェル、画像に偽装した PHP、`.htaccess` の `auto_prepend_file` など。ルールは `agent/rules/patterns.php` |
| 公式配布版との照合 | WordPress 本体と公式リポジトリのプラグインを WordPress.org のチェックサムと照合する。一致すれば正規の更新として通知しない。改ざんされたコアファイルや、コアディレクトリに紛れ込んだファイルは 🔴緊急 |
| 導入時点の検査 | ベースラインを作るときにも全ファイルを検査し、すでに置かれているマルウェアを通知する |
| 重要度の判定 | uploads 内の PHP、`.htaccess`、`wp-config.php`、mu-plugins、drop-in、公開ディレクトリ直下の見慣れない PHP は 🔴緊急 |
| Slack 通知 | 重複を抑止し、大量の変更は 1 通にまとめる。送信に失敗したら次回のスキャンで再送する |
| サイトの消失検知 | 監視していたサイトが見つからなくなったら通知する |
| 隔離 | 検知したファイルをサイトから取り除き、root だけが読める場所に保管する。元に戻せる。30 日で自動削除 |
| 日次サマリー | 毎朝 1 通。問題のあるサイト (未対応の検知、止まっているスキャン、消えたサイト) だけを並べる |
| WAF の集計 | ModSecurity を入れていれば、日次サマリーに遮断の件数 (サイト・接続元・攻撃の種類) を載せる ([docs/modsecurity.md](docs/modsecurity.md)) |
| DB の検査 | 毎日の全件スキャンで、各サイトの DB を読み取り専用で検査する。投稿や設定 (ウィジェットなど) に埋め込まれた難読化スクリプト・IP アドレスからのスクリプト・見えない iframe・新しい外部ドメインのスクリプト、サイト URL の書き換え、管理者の増減 |

**DB の検査について**: 接続情報は各サイトの `wp-config.php` から読み取ります (実行はしません)。初回の検査では、すでに埋め込まれている外部スクリプト (アクセス解析や広告など) は記録だけして通知しません。それ以降に新しいドメインのスクリプトが埋め込まれたら通知します。よく使われるサービス (Google アナリティクスなど) は `db_script_allow` で許可済みです。

二要素認証やログイン保護などは、各サイトのプラグインが担当します ([plugin/README.md](plugin/README.md))。
SQL インジェクションなどの攻撃を入口で遮断する WAF は、Apache の ModSecurity を使います ([docs/modsecurity.md](docs/modsecurity.md))。

**照合できないもの**: テーマと、公式リポジトリにない有料プラグインは比べる相手がないため、場所による判定とパターン検出だけになります (更新すると 🟡警告で通知されます)。

**通信**: 公式チェックサムの取得に `api.wordpress.org` と `downloads.wordpress.org` への HTTPS 通信が必要です。通信できないときは照合を飛ばし、それ以外の検査は続けます。

## 動作環境

- PHP 8.1 以上 (CLI)、拡張モジュール `pdo_sqlite`・`curl`・`mbstring`・`tokenizer`・`pdo_mysql` (DB の検査用)
- root で実行すること (全サイトのファイルを読むため。また、状態データを www-data から守るため)

```bash
sudo apt-get install -y php-cli php-sqlite3 php-curl php-mbstring php-mysql
```

## インストール

```bash
sudo ./agent/install.sh                  # /opt/wpguard、コマンド、cron を入れる (更新も同じ)
sudo vi /opt/wpguard/config.php          # roots と slack.webhook_url を設定
```

### 動作確認

```bash
sudo wpguard sites                 # サイトが検出されているか
sudo wpguard test-slack            # Slack に届くか
sudo wpguard scan --dry-run -v     # 初回: ベースライン作成 (通知は画面に表示するだけ)
```

`--dry-run` で作ったベースラインもそのまま使われます。

### cron の設定

`install.sh` が `/etc/cron.d/wpguard` に次の内容を置きます。

```
0 * * * *   root  nice -n 19 ionice -c3 /opt/wpguard/bin/wpguard scan
30 3 * * *  root  nice -n 19 ionice -c3 /opt/wpguard/bin/wpguard scan --full
0 9 * * *   root  /opt/wpguard/bin/wpguard digest
```

毎朝 9 時に、全サイトの状態をまとめた日次サマリーが届きます。異常がなければ「✅ 異常はありません」の短い 1 通です。
**日次サマリーが届かない日は、監視エージェント自体が止まっています** (サーバーの停止、cron の設定ミスなど)。

### Apache の設定 (推奨)

uploads 内で PHP が実行されないようにします。`.htaccess` は攻撃者に書き換えられる可能性があるため、Apache 本体の設定に入れてください。

[`docs/apache/wpguard-uploads.conf`](docs/apache/wpguard-uploads.conf) をそのまま使えます (導入手順は [docs/deploy.md](docs/deploy.md) の段階 3)。

```apache
# /etc/apache2/conf-available/wpguard-uploads.conf

# 1. uploads の .htaccess では、アクセス制限 (Require / deny from all) だけを許可する。
#    攻撃者が「.jpg を PHP として実行する」設定 (AddHandler など) を書いても効かない。
#    WooCommerce などがファイルを守るための .htaccess は、そのまま効く。
#    (AllowOverride は正規表現の <DirectoryMatch> では使えないため、階層ごとに書く)
<Directory "/var/www/*/wp-content/uploads">
    AllowOverride AuthConfig Limit
</Directory>
<Directory "/var/www/*/*/wp-content/uploads">
    AllowOverride AuthConfig Limit
</Directory>

# 2. uploads 内の PHP ファイルへのアクセスを拒否する。
<DirectoryMatch "^/var/www/.+/wp-content/uploads">
    <FilesMatch "\.(?i:php[0-9]?|phtml|pht|phar|phps|inc)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
```

`/var/www/サイト/wp-content/uploads` と `/var/www/サイト/public_html/wp-content/uploads` の 2 つの構成に対応しています。ほかの構成のサイトがあれば、`<Directory>` の行を足してください。

**攻撃者が uploads に `.htaccess` を置いた場合**: 許可していない命令が含まれるため、uploads 全体が 500 エラーになります (画像が表示されなくなります)。マルウェアは実行されず、監視エージェントも 🔴緊急で通知するので、`.htaccess` を削除してください。

Apache 2.4.54 + PHP 7.4 で確認した結果:

| uploads の状態 | `shell.php` | PHP を仕込んだ `shell.jpg` | 画像 | WooCommerce の保護ファイル |
|---|---|---|---|---|
| `.htaccess` なし | 403 | 実行しない | 表示 | 403 |
| WPGuard Sentinel の `.htaccess` | 403 | 実行しない | 表示 | 403 |
| 攻撃者の `.htaccess` | 500 | 500 (実行しない) | 500 | 500 |

この設定がない場合、攻撃者の `.htaccess` で `shell.php` も `shell.jpg` も実行されることを確認しています。

```bash
sudo a2enconf wpguard-uploads && sudo apachectl configtest && sudo systemctl reload apache2
```

## 使い方

```bash
wpguard findings                     # 未対応の検知の一覧
wpguard findings --site=example.com
wpguard ack 12 13                    # 確認済みにする
wpguard ack --site=example.com --all
wpguard baseline --site=example.com  # 現在の状態を正常として記録し直す (有料プラグインやテーマの更新後など)
wpguard db-scan --site=example.com   # DB だけを今すぐ検査する
wpguard 2fa-reset --site=example.com --user=tanaka   # 二要素認証を解除する (スマホと予備コードを両方なくしたとき)
wpguard help
```

### マルウェアを見つけたら

```bash
wpguard quarantine 12                # 検知 #12 のファイルを隔離する (Slack の通知にもコマンドが出ます)
wpguard quarantine --site=example.com --path=wp-content/uploads/x.php
wpguard quarantine --list            # 隔離したファイルの一覧
wpguard restore 3                    # 隔離 ID #3 を元に戻す (誤検知だったとき)
```

隔離したファイルは `/var/lib/wpguard/quarantine/` に保管されます (調査用に中身はそのまま)。

**WordPress 本体・プラグイン・テーマのファイルは隔離できません** (サイトが動かなくなるため)。改ざんされていたら入れ直してください。どうしても隔離する場合は `--force` を付けます。

```bash
# WP-CLI の例 (サイトのディレクトリで、サイトの所有者として実行)
wp core download --force --skip-content --version=$(wp core version)
wp plugin install <プラグイン名> --force
```

ファイルを取り除いても、侵入された原因 (古いプラグイン、漏れたパスワードなど) が残っていれば、また置かれます。管理者のパスワード変更と、原因の調査も行ってください。

## 検出ルールの調整

`agent/rules/patterns.php` にルールがあります。誤検知が多いルールは `severity` を下げるか削除してください。
ルールを変えたら、次の全件スキャン (`wpguard scan --full`) で既存のファイルにも適用されます。

## 開発

```bash
php agent/tests/run.php     # 監視エージェント
php agent/tests/dbscan.php  # DB の検査 (Docker で MariaDB を起動して試す)
php plugin/tests/e2e.php    # プラグイン (本物の WordPress で試す)
```
