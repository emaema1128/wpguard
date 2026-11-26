<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * A-08: moves suspicious files out of the site into a root-only directory,
 * so they can no longer run, but can be inspected or put back.
 */
final class Quarantine
{
    private const CORE_ROOT_FILES = [
        'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config.php',
        'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
        'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
    ];

    public function __construct(private Database $db, private string $dir)
    {
    }

    /**
     * @param array<string,mixed> $site row from the sites table
     * @return array{id:int,path:string,sha256:?string}
     */
    public function isolate(array $site, string $rel, ?int $findingId, bool $force, int $now): array
    {
        if (str_starts_with($rel, 'db:')) {
            throw new \RuntimeException("DB の中の検知 ({$rel}) は隔離できません。管理画面で該当の投稿・設定・ユーザーを確認して直してください。");
        }
        $rel = self::normalize($rel);
        $root = (string) $site['path'];
        $abs = $root . '/' . $rel;

        $st = @lstat($abs);
        if ($st === false) {
            throw new \RuntimeException("ファイルが見つかりません: {$rel} (すでに削除されている可能性があります)");
        }
        $kind = $st['mode'] & 0170000;
        if ($kind !== 0100000 && $kind !== 0120000) {
            throw new \RuntimeException("通常のファイルではないため隔離できません: {$rel}");
        }
        // The parent directory must really be inside the site (no symlinked directories leading elsewhere).
        $parent = realpath(dirname($abs));
        if ($parent === false || ($parent !== $root && !str_starts_with($parent . '/', $root . '/'))) {
            throw new \RuntimeException("サイトの外を指しているため隔離できません: {$rel}");
        }
        if (!$force) {
            $why = self::breaksSite($rel);
            if ($why !== null) {
                throw new \RuntimeException($why . "\nそれでも隔離する場合は --force を付けてください。");
            }
        }

        $isLink = $kind === 0120000;
        $sha = $isLink ? null : (@hash_file('sha256', $abs) ?: null);
        $id = $this->db->insertQuarantine([
            'site_id' => (int) $site['id'],
            'finding_id' => $findingId,
            'path' => $rel,
            'sha256' => $sha,
            'size' => (int) $st['size'],
            'mode' => $st['mode'] & 07777,
            'uid' => (int) $st['uid'],
            'gid' => (int) $st['gid'],
            'mtime' => (int) $st['mtime'],
            'is_link' => $isLink ? 1 : 0,
            'quarantined_at' => $now,
        ]);

        $box = $this->dir . '/' . $id;
        $stored = $box . '/' . str_replace('/', '__', $rel) . '.quarantined';
        try {
            if (!@mkdir($box, 0700, true) && !is_dir($box)) {
                throw new \RuntimeException("隔離用ディレクトリを作成できません: {$box}");
            }
            if ($isLink) {
                file_put_contents($stored, (string) readlink($abs));
                if (!@unlink($abs)) {
                    throw new \RuntimeException("シンボリックリンクを削除できません: {$rel}");
                }
            } else {
                self::move($abs, $stored);
            }
        } catch (\Throwable $e) {
            if (@lstat($abs) !== false) {
                @unlink($stored);
                @rmdir($box);
            }
            $this->db->deleteQuarantine($id);
            throw $e;
        }
        @chmod($stored, 0600);

        $this->db->updateQuarantine($id, ['stored' => $stored]);
        $this->db->deleteFile((int) $site['id'], $rel);
        $this->db->setFindingStatus((int) $site['id'], $rel, 'quarantined', $now);

        return ['id' => $id, 'path' => $rel, 'sha256' => $sha];
    }

    /** @return array<string,mixed> the quarantine row, with the site path */
    public function restore(int $id, int $now): array
    {
        $q = $this->db->quarantineEntry($id);
        if ($q === null) {
            throw new \RuntimeException("隔離 ID #{$id} が見つかりません (wpguard quarantine --list で確認できます)");
        }
        if ($q['restored_at'] !== null || $q['purged_at'] !== null) {
            throw new \RuntimeException("隔離 ID #{$id} は、すでに元に戻したか、保管期間が過ぎて削除されています");
        }
        $abs = $q['site_path'] . '/' . $q['path'];
        if (@lstat($abs) !== false) {
            throw new \RuntimeException("元の場所に別のファイルがあるため戻せません: {$q['path']}");
        }
        $dir = dirname($abs);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
            throw new \RuntimeException("元のディレクトリを作成できません: {$dir}");
        }

        if ((int) $q['is_link'] === 1) {
            if (!@symlink((string) file_get_contents((string) $q['stored']), $abs)) {
                throw new \RuntimeException("シンボリックリンクを作成できません: {$q['path']}");
            }
            @unlink((string) $q['stored']);
        } else {
            self::move((string) $q['stored'], $abs);
            @chmod($abs, (int) $q['mode']);
            if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
                @chown($abs, (int) $q['uid']);
                @chgrp($abs, (int) $q['gid']);
            }
            @touch($abs, (int) $q['mtime']);
        }
        @rmdir(dirname((string) $q['stored']));

        // Record it as known so the next scan does not report it as a new file.
        // ctime 0 makes the next scan re-hash it once (see Scanner), which finds the same contents.
        clearstatcache();
        $st = lstat($abs);
        $this->db->upsertFile((int) $q['site_id'], (string) $q['path'], [
            'type' => (int) $q['is_link'] === 1 ? FileWalker::TYPE_LINK : FileWalker::TYPE_FILE,
            'size' => (int) $st['size'],
            'mtime' => (int) $st['mtime'],
            'ctime' => 0,
            'inode' => (int) $st['ino'],
        ], (int) $q['is_link'] === 1 ? 'link:' . hash('sha256', (string) readlink($abs)) : $q['sha256']);
        $this->db->updateQuarantine($id, ['restored_at' => $now]);
        $this->db->setFindingStatus((int) $q['site_id'], (string) $q['path'], 'acked', $now, 'quarantined');
        return $q;
    }

    /** Deletes quarantined files older than the retention period. */
    public function purge(int $before, int $now): int
    {
        $n = 0;
        foreach ($this->db->quarantineEntries() as $q) {
            if ($q['restored_at'] !== null || $q['purged_at'] !== null || (int) $q['quarantined_at'] >= $before) {
                continue;
            }
            if ($q['stored'] !== null) {
                @unlink((string) $q['stored']);
                @rmdir(dirname((string) $q['stored']));
            }
            $this->db->updateQuarantine((int) $q['id'], ['purged_at' => $now]);
            $n++;
        }
        return $n;
    }

    /** Why removing this file would take the site down, or null when it is safe to remove. */
    public static function breaksSite(string $rel): ?string
    {
        $base = basename($rel);
        if ($rel === 'wp-config.php') {
            return 'wp-config.php を隔離するとサイトが表示されなくなります。不正なコードを手で取り除いてください。';
        }
        if (OfficialVerifier::isCoreDir($rel) || (!str_contains($rel, '/') && in_array($base, self::CORE_ROOT_FILES, true))) {
            return "WordPress 本体のファイルを隔離すると、サイトが動かなくなります。\n"
                . '改ざんされたコアファイルは、WordPress の再インストールで正しいファイルに戻してください (例: wp core download --force --skip-content --version=<今のバージョン>)。';
        }
        if (preg_match('#^wp-content/(plugins|themes)/([^/]+)/#', $rel, $m)) {
            [$what, $cli] = $m[1] === 'plugins' ? ['プラグイン', 'plugin'] : ['テーマ', 'theme'];
            return "{$what} ({$m[2]}) のファイルを隔離すると、{$what}が動かなくなり、サイトが表示されなくなることがあります。\n"
                . "公式版がある場合は、{$what}を入れ直すのが確実です (例: wp {$cli} install {$m[2]} --force)。";
        }
        return null;
    }

    private static function normalize(string $rel): string
    {
        $rel = ltrim(str_replace('\\', '/', $rel), '/');
        if ($rel === '' || in_array('..', explode('/', $rel), true)) {
            throw new \RuntimeException("パスが不正です: {$rel}");
        }
        return $rel;
    }

    /** rename(), falling back to copy + delete when the data directory is on another disk. */
    private static function move(string $from, string $to): void
    {
        if (@rename($from, $to)) {
            return;
        }
        if (!@copy($from, $to)) {
            throw new \RuntimeException("ファイルを移動できません: {$from}");
        }
        if (!@unlink($from)) {
            @unlink($to);
            throw new \RuntimeException("元のファイルを削除できません: {$from}");
        }
    }
}
