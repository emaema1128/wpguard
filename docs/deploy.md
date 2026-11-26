# サーバーへの導入手順

VPS (Debian / Ubuntu、Apache) に WPGuard を入れる手順です。上から順に進めてください。各段階の最後に、うまくいったか確かめる方法を書いています。

| 段階 | 内容 | 時間の目安 | サイトへの影響 |
|---|---|---|---|
| 0 | 事前準備 | 1〜2 時間 | なし |
| 1 | 監視エージェントを入れる | 15 分 | なし |
| 2 | 最初のスキャンと、見つかったものの対応 | サイト数による | 不正なファイルを取り除く |
| 3 | Apache で uploads の PHP を止める | 10 分 | **Apache の再読み込み** |
| 4 | 各サイトにプラグインを入れる | 15 分 | **XML-RPC が止まる、二要素認証が始まる** |
| 5 | サイトごとの例外 | サイト数による | |
| 6 | 管理者への連絡 (二要素認証) | | |
| 7 | WAF (ModSecurity) | 別の手順書 | |
| 8 | 最終確認 | 15 分 | |

この手順は、Debian 13 / Apache 2.4 / PHP 8.4 / MariaDB 11.8 の検証用サーバーに WordPress を 2 サイト置き (1 サイトには侵入後に残ったマルウェアを仕込んだ状態)、上から順に実行して確かめています。

---

## 0. 事前準備

### 0-1. バックアップ

- [ ] 全サイトのファイルとデータベース
- [ ] Apache の設定: `sudo cp -a /etc/apache2 /root/apache2-backup-$(date +%Y%m%d)`

### 0-2. 用意するもの

- [ ] Slack の Incoming Webhook URL (通知を受けるチャンネル)
- [ ] サーバーに root (sudo) で入れるアカウント
- [ ] サーバー上の WPGuard のリポジトリ: `sudo git clone <リポジトリ> /root/wpguard`
- [ ] 各サイトの管理者の一覧 (二要素認証の連絡用)
- [ ] 次のサイトの洗い出し (段階 5 で使う)
  - Jetpack や WordPress のスマホアプリを使っているサイト
  - Cloudflare などのプロキシの後ろにあるサイト
  - ほかのサイトに iframe で埋め込んで見せているサイト

サーバーから `api.wordpress.org` と `downloads.wordpress.org` (公式チェックサムの取得)、`hooks.slack.com` (通知) に HTTPS で接続できる必要があります。

---

## 1. 監視エージェントを入れる

```bash
cd /root/wpguard
sudo ./agent/install.sh
```

PHP などの必要なパッケージ、プログラム (`/opt/wpguard`)、コマンド (`wpguard`)、cron (`/etc/cron.d/wpguard`) が入ります。

設定ファイルを編集します。

```bash
sudo vi /opt/wpguard/config.php
```

最低限、次の 2 つを設定します。

```php
'roots' => ['/var/www'],                          // サイトがある場所
'slack' => [
    'webhook_url' => 'https://hooks.slack.com/services/...',
    ...
```

### 確かめる

```bash
sudo wpguard test-slack     # Slack に「テスト通知です」が届く
sudo wpguard sites          # すべてのサイトが一覧に出る
```

サイトが足りないときは、`roots` と `discovery_max_depth` を見直してください。

---

## 2. 最初のスキャンと、見つかったものの対応

```bash
sudo wpguard scan
```

全サイトのファイルを記録し、同時に、すでに置かれているマルウェアを探します (公式版との照合、怪しいコードの検出、DB の検査)。サイトごとに「監視を開始しました」が Slack に届き、怪しいものがあれば続けて 🔴緊急 が届きます。

```bash
sudo wpguard findings       # 見つかったものの一覧
```

### 見つかったものの対応

| 見つかったもの | 対応 |
|---|---|
| uploads 内の PHP、見覚えのない PHP ファイル | `sudo wpguard quarantine <ID>` で隔離する |
| WordPress 本体のファイルの改ざん | 本体を入れ直す (`wp core download --force --skip-content --version=<今のバージョン>`、または管理画面の「更新」→「再インストール」) |
| プラグイン・テーマのファイルの改ざん | 入れ直す。テーマに数行書き足されているだけなら、その行を削除してもよい |
| DB の中の検知 (投稿・設定・管理者) | 管理画面で、該当の投稿・ウィジェット・ユーザーを確認して直す |
| 心当たりのあるもの (自作のコードなど) | `sudo wpguard ack <ID>` で確認済みにする |

隔離は削除ではありません。間違えたときは `sudo wpguard restore <隔離ID>` で戻せます。

ファイルを直したら、もう一度スキャンして確かめます。

```bash
sudo wpguard scan
sudo wpguard findings
```

直したファイルが公式版と一致すれば、そのファイルの検知は自動で「確認済み」になります。公式版と比べられないもの (テーマの改造など) は、確認して `ack` してください。

### 確かめる

- [ ] `sudo wpguard findings` が「未対応の検知はありません」になった
- [ ] 各サイトが表示される

---

## 3. Apache で uploads の PHP を止める

攻撃者がファイルをアップロードできても、実行できないようにします。

```bash
sudo cp /root/wpguard/docs/apache/wpguard-uploads.conf /etc/apache2/conf-available/
sudo a2enconf wpguard-uploads
sudo apache2ctl configtest          # Syntax OK を確認
sudo systemctl reload apache2
```

`/var/www/<サイト>/wp-content/uploads` と `/var/www/<サイト>/<public_html など>/wp-content/uploads` に効きます。ほかの場所にあるサイトは、設定ファイルの `<Directory>` を足してください。

### 確かめる

テスト用の PHP ファイルを 1 つ置いて、開けないことを確かめます (`example.com` と、サイトのパスは書き換えてください)。画像を一度もアップロードしていないサイトには uploads のフォルダがないので、画像のあるサイトで試してください。

```bash
echo '<?php echo "EXECUTED";' | sudo tee /var/www/example.com/public_html/wp-content/uploads/wpguard-test.php
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/wp-content/uploads/wpguard-test.php   # → 403
sudo wpguard scan     # 監視エージェントが「uploads 内の PHP ファイル」を 🔴緊急 で通知する (正しく動いている証拠)
sudo rm /var/www/example.com/public_html/wp-content/uploads/wpguard-test.php
sudo wpguard scan
sudo wpguard ack --site=example.com --all
```

---

## 4. 各サイトにプラグインを入れる

### 4-1. 共通設定

```bash
sudo mkdir -p /etc/wpguard
sudo cp /root/wpguard/plugin/sentinel.example.php /etc/wpguard/sentinel.php
sudo chown root:root /etc/wpguard/sentinel.php
sudo chmod 644 /etc/wpguard/sentinel.php
sudo vi /etc/wpguard/sentinel.php     # WPGUARD_SLACK_WEBHOOK を設定
```

### 4-2. 配置

```bash
cd /root/wpguard
sudo ./plugin/install.sh --dry-run /var/www    # 対象のサイトを確認
sudo ./plugin/install.sh /var/www
```

各サイトの `wp-content/mu-plugins/` にプラグインが入り、正規のファイルの一覧が `/etc/wpguard/sentinel.sha256` に書き出されます。監視エージェントはこの一覧と照らし合わせるので、**プラグインを入れても通知は出ません**。逆に、あとから誰かがプラグインのファイルを書き換えたら、🔴緊急で通知します。

**プラグインを入れた時点で、すべてのサイトで次のことが始まります。**

- XML-RPC (`xmlrpc.php`) が使えなくなる (Jetpack・スマホアプリを使うサイトは段階 5 で許可)
- 管理者の二要素認証が始まる (7 日間の猶予つき。段階 6 で連絡)
- ログイン試行の制限、管理画面でのファイル編集の禁止、セキュリティヘッダー

### 確かめる

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://example.com/xmlrpc.php    # → 403
curl -sI https://example.com/ | grep -i x-frame-options                           # → SAMEORIGIN
sudo wpguard scan && sudo wpguard findings                                       # → 未対応の検知はありません
```

- [ ] 各サイトが表示され、管理画面にログインできる (二要素認証の設定を促すお知らせが出る)

---

## 5. サイトごとの例外

例外は、そのサイトの `wp-config.php` に、`require_once ABSPATH . 'wp-settings.php';` より前に書きます。

| サイト | `wp-config.php` に書くこと |
|---|---|
| Jetpack や WordPress のスマホアプリを使う | `define('WPGUARD_ALLOW_XMLRPC', true);` |
| Cloudflare などのプロキシの後ろにある | `define('WPGUARD_TRUSTED_PROXIES', ['プロキシの IP', ...]);` (**必須**。書かないと、1 人がパスワードを 5 回間違えただけで全員がロックされます) |
| ほかのサイトに iframe で埋め込んで見せている | `define('WPGUARD_FRAME_OPTIONS', '');` |
| 外部サービスとの連携に、管理者のアプリケーションパスワードを使っている | `define('WPGUARD_2FA_ALLOW_APP_PASSWORDS', true);` |

そのほかの設定は [plugin/README.md](../plugin/README.md) を見てください。

`wp-config.php` を書き換えると、次のスキャンで監視エージェントが 🔴緊急 として通知します。自分たちの作業なので、確認したら `ack` してください。

---

## 6. 管理者への連絡 (二要素認証)

プラグインを入れた日から **7 日以内**に、各サイトの管理者に二要素認証を設定してもらいます。7 日を過ぎると、ログイン画面で設定しないと管理画面に入れなくなります。

連絡の例:

> 【お願い】WordPress の管理画面へのログインに、二要素認証を導入しました。
>
> **〇月〇日までに**、次の手順で設定してください。
>
> 1. スマホに認証アプリ (Google Authenticator、Microsoft Authenticator、1Password など) を入れる
> 2. WordPress の管理画面にログインし、上に出ているお知らせの「今すぐ設定する」を押す
> 3. 画面の「設定キー」をアプリに入力し、アプリに表示された 6 桁のコードを入力する
> 4. 最後に表示される **予備コード 10 個を、パスワード管理アプリなど安全な場所に保存する** (スマホをなくしたときに使います)
>
> 設定したあとは、ログインのたびにアプリのコードを入力します。スマホをなくして予備コードもない場合は、〇〇まで連絡してください。

予備コードもなくした人がいたら、サーバーで解除します。

```bash
sudo wpguard 2fa-reset --site=example.com --user=<ユーザー名>
```

---

## 7. WAF (ModSecurity)

SQL インジェクションなどの攻撃を入口で遮断します。手順は [modsecurity.md](modsecurity.md) にあります (1〜2 週間の様子見の期間があります)。

---

## 8. 最終確認

```bash
sudo wpguard sites          # 全サイトの「最終スキャン」が新しい
sudo wpguard findings       # 未対応の検知はありません
sudo wpguard digest         # Slack に日次サマリーが届く
cat /etc/cron.d/wpguard     # 毎時のスキャン、毎日 3:30 の全件スキャン、毎朝 9:00 の日次サマリー
```

- [ ] 翌朝 9 時に日次サマリーが届いた (**届かない朝は、監視エージェントが止まっています**)

---

## 運用

### 通知が来たら

| 通知 | まずやること |
|---|---|
| 🔴 怪しいコード、uploads 内の PHP、見慣れない PHP ファイル | 心当たりがなければ `wpguard quarantine <ID>`。そのあと侵入の経路を調べる (操作ログ、サーバーの syslog) |
| 🔴 コアファイル・WPGuard のファイルの改ざん | 入れ直す (WPGuard は `sudo ./plugin/install.sh /var/www`) |
| 🔴 管理者アカウントが作成された / 昇格した | 心当たりがなければ、そのアカウントを削除し、全管理者のパスワードを変更する |
| 🔴 ログインしていない状態でプラグインが有効化された | プラグインを無効化・削除し、侵入を疑う |
| 🔴 新しい定期実行の処理 (WP-Cron) | 通知に出ている「処理の場所」のファイルを確認し、不正なら隔離する |
| 🟡 IP アドレスをロックしました | 多くは攻撃。自分たちの IP なら、パスワードの確認を |
| 🟡 管理者が新しい IP からログインした | 本人に確認する |
| 🟡 プラグイン・テーマのファイルが変更された | 自分たちで更新したなら `ack` |

侵入を疑うときは、まずサーバーの syslog の操作ログを見てください。サイトの操作ログは消されている可能性があります。

```bash
sudo journalctl -t wpguard --since "2 days ago"
sudo grep 'wpguard:' /var/log/syslog | grep 'site=example.com'
```

### 自分たちの作業で通知が来るとき

| 作業 | 通知 | 対応 |
|---|---|---|
| WordPress 本体や、公式リポジトリのプラグインの更新 | 出ない (公式版と照合) | |
| 有料プラグイン・テーマの更新、テーマの編集 | 🟡警告 | `ack` (更新が多いときは `wpguard baseline --site=...`) |
| `wp-config.php` や `.htaccess` の編集 | 🔴緊急 | `ack` |
| サイトの追加・削除 | 🔵監視を開始しました / 🟡見つからなくなりました | |

### WPGuard の更新

```bash
cd /root/wpguard && sudo git pull
sudo ./agent/install.sh            # 設定ファイル (/opt/wpguard/config.php) はそのまま
sudo ./plugin/install.sh /var/www  # 正規のファイルの一覧も更新されるので、通知は出ない
```

### アンインストール

```bash
sudo rm -rf /var/www/*/wp-content/mu-plugins/wpguard-sentinel* /var/www/*/*/wp-content/mu-plugins/wpguard-sentinel*
sudo a2disconf wpguard-uploads && sudo systemctl reload apache2
sudo rm -f /etc/cron.d/wpguard /usr/local/bin/wpguard
sudo rm -rf /opt/wpguard /var/lib/wpguard /var/log/wpguard /etc/wpguard
```

各サイトの DB には、プラグインが作った操作ログのテーブル (`wp_wpguard_log`) と、`wpguard_` で始まる設定・ユーザー情報が残ります。
