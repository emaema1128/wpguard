#!/bin/sh
# WPGuard 監視エージェントをサーバーに入れる (更新も同じコマンド)
#
#   sudo ./install.sh            # 必要なパッケージも apt で入れる
#   sudo ./install.sh --no-apt   # パッケージは入れない
#
# 行うこと:
#   - /opt/wpguard にプログラムを置く (config.php は上書きしない)
#   - /usr/local/bin/wpguard からコマンドを使えるようにする
#   - データ (/var/lib/wpguard) とログ (/var/log/wpguard) の置き場所を root 専用で作る
#   - cron (/etc/cron.d/wpguard) を置く
# Apache の設定は変えません (docs/deploy.md の手順で行います)。
set -eu

APT=1
[ "${1:-}" = "--no-apt" ] && APT=""
if [ "$(id -u)" -ne 0 ]; then
  echo "root で実行してください (sudo ./install.sh)" >&2
  exit 1
fi

SRC=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/wpguard

if [ -n "$APT" ]; then
  echo "== パッケージ"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq php-cli php-sqlite3 php-curl php-mbstring php-mysql >/dev/null
fi
php -r 'exit(PHP_VERSION_ID >= 80100 ? 0 : 1);' || { echo "PHP 8.1 以上が必要です (現在: $(php -r 'echo PHP_VERSION;'))" >&2; exit 1; }
for ext in pdo_sqlite curl mbstring tokenizer pdo_mysql; do
  php -m | grep -qix "$ext" || { echo "PHP の拡張モジュール $ext がありません" >&2; exit 1; }
done

echo "== プログラム ($DEST)"
mkdir -p "$DEST"
for d in bin src rules; do
  rm -rf "$DEST/$d"
  cp -R "$SRC/$d" "$DEST/$d"
done
cp "$SRC/config.example.php" "$DEST/config.example.php"
NEW_CONFIG=""
if [ ! -f "$DEST/config.php" ]; then
  cp "$SRC/config.example.php" "$DEST/config.php"
  NEW_CONFIG=1
fi
chown -R root:root "$DEST"
chmod -R go-w "$DEST"
chmod 600 "$DEST/config.php"
chmod 755 "$DEST/bin/wpguard"
ln -sf "$DEST/bin/wpguard" /usr/local/bin/wpguard

echo "== データとログ"
install -d -m 700 -o root -g root /var/lib/wpguard
install -d -m 750 -o root -g root /var/log/wpguard

echo "== cron (/etc/cron.d/wpguard)"
cat > /etc/cron.d/wpguard <<'CRON'
# WPGuard 監視エージェント
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 * * * *   root  nice -n 19 ionice -c3 /opt/wpguard/bin/wpguard scan
30 3 * * *  root  nice -n 19 ionice -c3 /opt/wpguard/bin/wpguard scan --full
0 9 * * *   root  /opt/wpguard/bin/wpguard digest
CRON
chmod 644 /etc/cron.d/wpguard

echo
echo "インストールしました: $("$DEST/bin/wpguard" help | head -1)"
if [ -n "$NEW_CONFIG" ]; then
  echo "次に設定ファイルを編集してください: sudo vi $DEST/config.php (roots と slack.webhook_url)"
else
  echo "設定ファイル ($DEST/config.php) はそのままです。新しい設定項目は $DEST/config.example.php を見てください。"
fi

# cron runs in the server's time zone: on a UTC server "9:00" is 18:00 in Japan.
TZ_NAME=$(readlink /etc/localtime 2>/dev/null | sed -n 's#.*zoneinfo/##p')
if [ -n "$TZ_NAME" ] && [ "$TZ_NAME" != "Asia/Tokyo" ]; then
  echo
  echo "注意: サーバーのタイムゾーンが $TZ_NAME です。cron の時刻 (日次サマリーの 9:00 など) はこのタイムゾーンで動きます。"
  echo "      日本時間にするには: sudo timedatectl set-timezone Asia/Tokyo && sudo systemctl restart cron apache2"
fi
