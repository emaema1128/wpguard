# ModSecurity (WAF) の導入手順

Apache に ModSecurity と OWASP CRS (コアルールセット) を入れ、サーバー上の全サイトを SQL インジェクションや XSS などの攻撃から守ります。

- **ModSecurity**: Apache に組み込む WAF (届いたリクエストを調べて、攻撃を遮断する)
- **OWASP CRS**: ModSecurity で使う攻撃パターン集。専門家が保守していて、`apt` で更新される

WPGuard の監視エージェントとサイト用プラグインとは独立して動きます。WAF はログイン試行の回数制限や二要素認証をしないので、プラグインも引き続き必要です。

## 進め方

| 段階 | やること | 期間の目安 |
|---|---|---|
| 1. 導入 | パッケージを入れ、**記録だけ** (遮断しない) モードで動かす | 30 分 |
| 2. 様子見 | ログを見て、正規の操作が「遮断されるはずだった」ものを探し、外す | 1〜2 週間 |
| 3. 遮断 | 遮断モードに切り替える | 5 分 |

いきなり遮断モードにしないでください。サイトによって使っているプラグインや書く内容が違うので、思わぬ操作が遮断されることがあります。

## 確認済みの環境と結果

Debian 13 / Apache 2.4 / PHP 8.3 / ModSecurity 2.9.11 / CRS 3.3.7 / WordPress 7.1.5 で、次のとおり確認しています (遮断モード、下の `wpguard.conf` を適用した状態)。

| 確認したこと | 結果 |
|---|---|
| 攻撃 15 種類 (SQL インジェクション、XSS、パストラバーサル、コマンド実行、`php://` ラッパー、SSRF、Log4Shell など) | **すべて 403 で遮断** |
| 編集者の操作: 記号を含むパスワードでのログイン、ブロックエディタでの保存 (SQL の説明文、アクセス解析のタグ、YouTube の埋め込み、コードブロック、JavaScript のコード例、日本語の長文、300KB のページ)、ファイルのアップロード、自動保存 | **すべて通過** |
| 訪問者の操作: 日本語の文章 46 種類での検索、URL や引用符を含むコメント | **すべて通過** |
| WPGuard のプラグインの e2e テスト (ログイン、二要素認証、REST API など 104 項目) | 103 項目通過 (*) |

(*) 通らなかった 1 項目は、テスト環境がサイトを IP アドレス (`127.0.0.1`) で開いているために、oEmbed の引数が「IP アドレスを指す URL」と判定されたものです。ドメイン名で開く本番のサイトでは起きないと考えていますが、ドメイン名での確認はしていません。

**CRS の初期設定のままだと、日本語のサイトで深刻な誤検知が起きます。** 「コード例」「メール便」「サーバー設定例」のような普通の言葉で検索やコメントをすると、403 で遮断されました (ルール 941310)。下の `wpguard.conf` でこのルールを外しています。

## 1. 導入 (記録だけモード)

作業の前に、Apache の設定をバックアップしておきます。

```bash
sudo cp -a /etc/apache2 /root/apache2-backup-$(date +%Y%m%d)
```

### パッケージを入れる

```bash
sudo apt-get update
sudo apt-get install -y libapache2-mod-security2 modsecurity-crs
```

`security2` モジュールは自動で有効になります (`sudo apache2ctl -M | grep security` で `security2_module` が出れば OK)。

### ModSecurity の基本設定

```bash
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
grep '^SecRuleEngine' /etc/modsecurity/modsecurity.conf    # → SecRuleEngine DetectionOnly (記録だけ) になっていること
```

### WordPress 用の設定

[`docs/modsecurity/wpguard.conf`](modsecurity/wpguard.conf) を `/etc/modsecurity/wpguard.conf` に置きます。

```bash
sudo cp docs/modsecurity/wpguard.conf /etc/modsecurity/wpguard.conf
```

中身は次のとおりです。パッケージの設定ファイルは書き換えないので、`apt` で更新しても消えません。

| 設定 | 理由 |
|---|---|
| CRS の WordPress 向け除外ルールを有効にする | ブロックエディタでの保存などが遮断されないように |
| ファイル以外のデータの上限を 128KB → 2MB | ページビルダー (Elementor など) の保存が遮断されないように |
| ファイルを含むデータの上限を 12.5MB → 64MB | 大きなファイルのアップロードが遮断されないように。**PHP の `upload_max_filesize` / `post_max_size` に合わせて変えてください** |
| ルール 941310 を外す | 日本語の普通の言葉が XSS と判定されるため |

### 反映する

```bash
sudo apache2ctl configtest          # Syntax OK を確認
sudo systemctl reload apache2
```

### 動いているか確かめる

自分のサイトに、攻撃に見えるリクエストを 1 回送ります (害はありません)。

```bash
curl -s -o /dev/null -w '%{http_code}\n' "https://example.com/?id=1%27%20UNION%20SELECT%20user_pass%20FROM%20wp_users--"
sudo grep 'ModSecurity' /var/log/apache2/error.log | tail -3
```

記録だけモードなので、応答は `200` のままで、エラーログに `ModSecurity: Warning` の行が出れば成功です。

## 2. 様子見 (1〜2 週間)

普段どおりサイトを使ってもらい (投稿、固定ページの編集、フォームの送信、ネットショップの注文など)、**「遮断モードだったら遮断されていた」アクセスの中に、正規の操作がないか**を探します。

WPGuard の監視エージェントを入れていれば、毎朝の日次サマリーに件数が載ります (サイトごとの件数、多い接続元、攻撃の種類、多い URL)。自分たちの事務所の IP や、管理画面の URL が上位に出ていたら、下の手順で詳しく見てください。

```
🛡 WAF (24 時間、記録だけのモード): 遮断されるはずだったもの 23 件
  正規の操作が含まれていないか確認してください
  • サイト: shop.example 15 件 / blog.example 8 件
  • 多い接続元: 203.0.113.5 12 件 / …
  • 主な種類: SQL インジェクション 10 件 / XSS 6 件 / …
  • 多い URL: / 14 件 / /wp-login.php 5 件 / …
```

### ログの見かた

**(1) 遮断されていたはずのアクセスを、サイトと URL ごとに数える**

```bash
sudo zcat -f /var/log/apache2/error.log* | grep -E 'ModSecurity: (Warning|Access denied).*id "949110"' \
  | grep -oE '\[hostname "[^"]+"\]|\[uri "[^"]+"\]' | paste -d' ' - - | sort | uniq -c | sort -rn | head -30
```

攻撃のほうが多いはずです。自分たちが使っている管理画面の URL (`/wp-admin/...`、`/wp-json/...`) や、フォームの送信先がないかを見てください。

**(2) 気になる URL で、どのルールが、どの項目に反応したかを見る**

```bash
sudo zcat -f /var/log/apache2/error.log* | grep 'ModSecurity' | grep '\[uri "/wp-admin/admin-ajax.php"\]' \
  | grep -vE 'id "(949110|980130)"' \
  | sed -nE 's/.*\[id "([0-9]+)"\].*found within ([A-Z_]+:[^: ]+).*/ルール \1  項目 \2/p' | sort | uniq -c | sort -rn
```

`949110` と `980130` は「合計点が基準を超えた」という集計のルールなので除いています。残ったものが、実際に反応したルールです。

**(3) 誰のアクセスか (攻撃か、自分たちか) を確かめる**

エラーログの行の `[client 203.0.113.10]` が接続元の IP です。自分たちの事務所の IP や、WPGuard の操作ログ (ツール → 操作ログ) の時刻と照らし合わせます。

### 誤検知の外し方

`/etc/modsecurity/wpguard.conf` の末尾に追記します。**外す範囲はできるだけ狭くしてください** (広く外すほど、攻撃も通ります)。

`id` は `1000000`〜`1099999` の範囲で、重ならない番号を付けます。

```apache
# 例 1: ある URL でだけ、あるルールを外す (一番よく使う)
SecRule REQUEST_FILENAME "@beginsWith /wp-admin/admin-ajax.php" \
    "id:1000101,phase:1,nolog,pass,t:none,ctl:ruleRemoveById=941160"

# 例 2: ある URL の、ある項目だけ、あるルールの対象から外す (いちばん安全)
SecRule REQUEST_FILENAME "@beginsWith /wp-json/contact-form-7/" \
    "id:1000102,phase:1,nolog,pass,t:none,ctl:ruleRemoveTargetById=942100;ARGS:your-message"

# 例 3: あるサイトでだけ、あるルールを外す
SecRule SERVER_NAME "@streq shop.example.com" \
    "id:1000103,phase:1,nolog,pass,t:none,ctl:ruleRemoveById=941100"

# 例 4: ルールをすべてのサイトで外す (最後の手段)
SecAction "id:1000020,phase:1,nolog,pass,t:none,ctl:ruleRemoveById=942100"
```

書いたら反映します。

```bash
sudo apache2ctl configtest && sudo systemctl reload apache2
```

## 3. 遮断モードに切り替える

様子見で見つかった誤検知を外したら、切り替えます。

```bash
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sudo apache2ctl configtest && sudo systemctl reload apache2
curl -s -o /dev/null -w '%{http_code}\n' "https://example.com/?id=1%27%20UNION%20SELECT%20user_pass%20FROM%20wp_users--"   # → 403
```

遮断モードにしてからは、日次サマリーに「🛡 WAF (24 時間): 遮断 N 件」が載ります。1 件の攻撃が複数の種類 (例: ファイルの読み出しとコマンドの実行) に数えられることがあります。

遮断モードにしてからしばらくは、サイトの利用者から「403 Forbidden が出る」という連絡がないか気をつけてください。連絡があったら、その時刻と URL でエラーログを探し (上の (2))、誤検知なら外します。

## 困ったとき

### すぐに WAF を止めたい

```bash
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf   # 記録だけに戻す
sudo systemctl reload apache2
```

完全に外す場合は `sudo a2dismod security2 && sudo systemctl restart apache2` です。

### 遮断の画面

遮断されたアクセスには、Apache の標準の「403 Forbidden」が返ります。

## 注意

- **パーマリンク設定は「基本」以外に**: CRS の WordPress 向け除外ルールは、`/wp-json/` の形の URL を前提にしています。パーマリンクが「基本」(`?p=123`) のサイトは、ブロックエディタの保存が `?rest_route=` の形になり、除外ルールが効かない可能性があります (この組み合わせは確認していません)。
- **タイトルに `<script>` や `/etc/passwd` をそのまま書くと遮断されます**: 本文に書くのは問題ありません (確認済み)。
- **XML-RPC**: WPGuard のプラグインは XML-RPC を止めます。Jetpack などのために許可しているサイトについては、簡単な XML-RPC のリクエスト (`system.listMethods`) が ModSecurity に遮断されないことだけを確認しています。Jetpack の実際の通信は確認していないので、様子見の段階で `/xmlrpc.php` のログを見てください。
- **ログの量**: ModSecurity のログ (`/var/log/apache2/modsec_audit.log` と `error.log`) は、Apache のログと一緒に毎日ローテーションされます (Debian の初期設定)。攻撃が多いと大きくなるので、ディスクの空きに注意してください。
- **パラノイアレベル**: CRS の厳しさは 1 (初期値) のままにしています。上げると防げる攻撃は増えますが、誤検知も大幅に増えます。
- **CRS の更新**: `apt` でパッケージを更新すると、ルールも新しくなります。更新後に誤検知が増えていないか、しばらくログを見てください。
- **Ubuntu**: パッケージ名と設定ファイルの場所は同じですが、CRS のバージョンが違う場合があります。様子見の段階で確認してください。

## 検証の再現

この手順書の確認は、次の手順でやり直せます (CRS を更新したときなど)。手元の Docker で動き、本番のサーバーには触れません。

```bash
docker build -t wpguard-modsec -f docs/modsecurity/Dockerfile docs/modsecurity
WPGUARD_E2E_KEEP=1 WPGUARD_E2E_IMAGE=wpguard-modsec php plugin/tests/e2e.php

# 編集者ユーザーとパーマリンクを用意する (パスは e2e の出力に合わせて)
docker exec wpguard-e2e sh -c 'a2enmod -q rewrite && apache2ctl -k graceful'
docker exec -u www-data wpguard-e2e php plugin/tests/wp-exec.php <サイトのパス> \
  'wp_insert_user(wp_slash(["user_login" => "eddie", "user_pass" => "Ed1tor-P@ss'"'"'word", "role" => "editor", "user_email" => "e@example.com"])); update_option("permalink_structure", "/%postname%/");'
# サイトのパスに WordPress 標準の .htaccess を置き、wp-content/uploads を書き込み可能にする

php plugin/tests/modsecurity-check.php "Ed1tor-P@ss'word"
docker rm -f wpguard-e2e wpguard-e2e-db
```
