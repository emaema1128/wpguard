# WPGuard

VPS 上の複数の WordPress サイトを監視し、マルウェアの設置や改ざんを Slack に通知するツールです。

- `agent/` … 監視エージェント (サーバー側で cron 実行)
- `plugin/` … 各サイトに入れるプラグイン (未実装)

## 現在できること (ステップ 1〜2)

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

**まだできないこと**: 疑わしいファイルの隔離、DB 内に注入されたスクリプトの検出、各サイトのプラグイン (ログイン保護など)。

**照合できないもの**: テーマと、公式リポジトリにない有料プラグインは比べる相手がないため、場所による判定とパターン検出だけになります (更新すると 🟡警告で通知されます)。

**通信**: 公式チェックサムの取得に `api.wordpress.org` と `downloads.wordpress.org` への HTTPS 通信が必要です。通信できないときは照合を飛ばし、それ以外の検査は続けます。

## 動作環境

- PHP 8.1 以上 (CLI)、拡張モジュール `pdo_sqlite`・`curl`・`mbstring`
- root で実行すること (全サイトのファイルを読むため。また、状態データを www-data から守るため)

```bash
sudo apt-get install -y php-cli php-sqlite3 php-curl php-mbstring
```

## インストール

```bash
sudo cp -r agent /opt/wpguard
sudo chown -R root:root /opt/wpguard
sudo chmod -R go-w /opt/wpguard

sudo cp /opt/wpguard/config.example.php /opt/wpguard/config.php
sudo chmod 600 /opt/wpguard/config.php
sudo vi /opt/wpguard/config.php          # roots と slack.webhook_url を設定

sudo ln -s /opt/wpguard/bin/wpguard /usr/local/bin/wpguard
```

### 動作確認

```bash
sudo wpguard sites                 # サイトが検出されているか
sudo wpguard test-slack            # Slack に届くか
sudo wpguard scan --dry-run -v     # 初回: ベースライン作成 (通知は画面に表示するだけ)
```

`--dry-run` で作ったベースラインもそのまま使われます。

### cron の設定

`/etc/cron.d/wpguard`:

```
0 * * * *   root  nice -n 19 ionice -c3 /opt/wpguard/bin/wpguard scan
30 3 * * *  root  nice -n 19 ionice -c3 /opt/wpguard/bin/wpguard scan --full
```

### Apache の設定 (推奨)

uploads 内で PHP が実行されないようにします。`.htaccess` は攻撃者に消される可能性があるため、Apache 本体の設定に入れてください。

```apache
# /etc/apache2/conf-available/wpguard.conf
<DirectoryMatch "^/var/www/.+/wp-content/uploads">
    <FilesMatch "\.(php|phtml|phar|php\d)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
```

```bash
sudo a2enconf wpguard && sudo apachectl configtest && sudo systemctl reload apache2
```

## 使い方

```bash
wpguard findings                     # 未対応の検知の一覧
wpguard findings --site=example.com
wpguard ack 12 13                    # 確認済みにする
wpguard ack --site=example.com --all
wpguard baseline --site=example.com  # 現在の状態を正常として記録し直す (有料プラグインやテーマの更新後など)
wpguard help
```

## 検出ルールの調整

`agent/rules/patterns.php` にルールがあります。誤検知が多いルールは `severity` を下げるか削除してください。
ルールを変えたら、次の全件スキャン (`wpguard scan --full`) で既存のファイルにも適用されます。

## 開発

```bash
cd agent
php tests/run.php
```
