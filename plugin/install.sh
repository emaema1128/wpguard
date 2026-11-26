#!/bin/sh
# WPGuard Sentinel を、指定したディレクトリの下にあるすべての WordPress に入れる (更新も同じ手順)
#
#   sudo ./install.sh --dry-run /var/www    # 何をするか表示するだけ
#   sudo ./install.sh /var/www
#
# プラグインのファイルは root 所有にして、Web サーバーのユーザーから書き換えられないようにします。
set -eu

DRY=""
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
if [ $# -eq 0 ]; then echo "使い方: $0 [--dry-run] <ディレクトリ>..." >&2; exit 1; fi

SRC=$(cd "$(dirname "$0")" && pwd)
run() { if [ -n "$DRY" ]; then echo "  [dry-run] $*"; else "$@"; fi; }

LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT
# wp-includes/version.php がある場所を WordPress とみなす (シンボリックリンクはたどらない)
for root in "$@"; do
  find "$root" -maxdepth 6 -path '*/wp-includes/version.php' -type f -not -path '*/wp-content/*' 2>/dev/null >> "$LIST"
done

count=0
while IFS= read -r version; do
  site=$(dirname "$(dirname "$version")")
  [ -d "$site/wp-content" ] || continue
  mu="$site/wp-content/mu-plugins"
  echo "$site"
  if [ ! -d "$mu" ]; then
    run mkdir "$mu"
    run chown root:root "$mu"
    run chmod 755 "$mu"
  fi
  run rm -rf "$mu/wpguard-sentinel"
  run cp -R "$SRC/wpguard-sentinel" "$mu/wpguard-sentinel"
  run cp "$SRC/wpguard-sentinel.php" "$mu/wpguard-sentinel.php"
  run chown -R root:root "$mu/wpguard-sentinel" "$mu/wpguard-sentinel.php"
  run chmod -R u=rwX,go=rX "$mu/wpguard-sentinel" "$mu/wpguard-sentinel.php"
  count=$((count + 1))
done < "$LIST"

# The monitoring agent compares the deployed files with this list, so installing or updating
# the plugin is not reported as a new mu-plugin, while any change to it still is.
MANIFEST=/etc/wpguard/sentinel.sha256
if [ -z "$DRY" ]; then
  mkdir -p /etc/wpguard
  (cd "$SRC" && find wpguard-sentinel wpguard-sentinel.php -type f -print0 | sort -z | xargs -0 sha256sum) > "$MANIFEST.tmp"
  mv "$MANIFEST.tmp" "$MANIFEST"
  chown root:root "$MANIFEST"
  chmod 644 "$MANIFEST"
fi

echo "${count} サイトに配置しました${DRY:+ (dry-run のため実際には何もしていません)}"
if [ ! -r /etc/wpguard/sentinel.php ]; then
  echo "注意: /etc/wpguard/sentinel.php がありません。sentinel.example.php を参考に作成してください。" >&2
fi
