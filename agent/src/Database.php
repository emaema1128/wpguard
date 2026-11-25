<?php

declare(strict_types=1);

namespace WPGuard;

final class Database
{
    private \PDO $pdo;
    private ?\PDOStatement $upsertFile = null;
    private ?\PDOStatement $deleteFile = null;
    private ?\PDOStatement $insertFinding = null;

    public function __construct(string $file)
    {
        $this->pdo = new \PDO('sqlite:' . $file, null, null, [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);
        $this->pdo->exec('PRAGMA journal_mode = WAL');
        $this->pdo->exec('PRAGMA foreign_keys = ON');
        $this->pdo->exec('PRAGMA busy_timeout = 5000');
        $this->migrate();
    }

    private function migrate(): void
    {
        $version = (int) $this->pdo->query('PRAGMA user_version')->fetchColumn();
        if ($version < 1) {
            $this->pdo->exec(<<<'SQL'
                CREATE TABLE sites (
                    id INTEGER PRIMARY KEY,
                    path TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    wp_version TEXT,
                    first_seen INTEGER NOT NULL,
                    last_scan INTEGER,
                    baseline_done INTEGER NOT NULL DEFAULT 0,
                    missing_since INTEGER
                );
                CREATE TABLE files (
                    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime INTEGER NOT NULL,
                    ctime INTEGER NOT NULL,
                    inode INTEGER NOT NULL,
                    sha256 TEXT,
                    PRIMARY KEY (site_id, path)
                ) WITHOUT ROWID;
                CREATE TABLE findings (
                    id INTEGER PRIMARY KEY,
                    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    message TEXT NOT NULL,
                    sha256 TEXT,
                    status TEXT NOT NULL,
                    detected_at INTEGER NOT NULL,
                    notified_at INTEGER,
                    resolved_at INTEGER
                );
                CREATE INDEX findings_status ON findings (status, site_id);
                CREATE TABLE notifications (
                    fingerprint TEXT PRIMARY KEY,
                    sent_at INTEGER NOT NULL
                ) WITHOUT ROWID;
                PRAGMA user_version = 1;
                SQL);
        }
    }

    public function begin(): void
    {
        $this->pdo->beginTransaction();
    }

    public function commit(): void
    {
        $this->pdo->commit();
    }

    public function rollBack(): void
    {
        if ($this->pdo->inTransaction()) {
            $this->pdo->rollBack();
        }
    }

    // ---- sites ----

    /** @return array<string,array<string,mixed>> keyed by path */
    public function sites(): array
    {
        $rows = $this->pdo->query('SELECT * FROM sites ORDER BY name')->fetchAll();
        return array_column($rows, null, 'path');
    }

    public function insertSite(Site $site, int $now): int
    {
        $st = $this->pdo->prepare('INSERT INTO sites (path, name, wp_version, first_seen) VALUES (?, ?, ?, ?)');
        $st->execute([$site->path, $site->name, $site->wpVersion, $now]);
        return (int) $this->pdo->lastInsertId();
    }

    public function updateSite(int $id, array $fields): void
    {
        $set = implode(', ', array_map(static fn ($k) => "{$k} = ?", array_keys($fields)));
        $st = $this->pdo->prepare("UPDATE sites SET {$set} WHERE id = ?");
        $st->execute([...array_values($fields), $id]);
    }

    // ---- files ----

    /** @return array<string,array<string,mixed>> keyed by relative path */
    public function files(int $siteId): array
    {
        $st = $this->pdo->prepare('SELECT path, type, size, mtime, ctime, inode, sha256 FROM files WHERE site_id = ?');
        $st->execute([$siteId]);
        $out = [];
        while ($row = $st->fetch()) {
            $out[$row['path']] = $row;
        }
        return $out;
    }

    public function upsertFile(int $siteId, string $path, array $stat, ?string $sha256): void
    {
        $this->upsertFile ??= $this->pdo->prepare(<<<'SQL'
            INSERT INTO files (site_id, path, type, size, mtime, ctime, inode, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (site_id, path) DO UPDATE SET
                type = excluded.type, size = excluded.size, mtime = excluded.mtime,
                ctime = excluded.ctime, inode = excluded.inode, sha256 = excluded.sha256
            SQL);
        $this->upsertFile->execute([
            $siteId, $path, $stat['type'], $stat['size'], $stat['mtime'], $stat['ctime'], $stat['inode'], $sha256,
        ]);
    }

    public function deleteFile(int $siteId, string $path): void
    {
        $this->deleteFile ??= $this->pdo->prepare('DELETE FROM files WHERE site_id = ? AND path = ?');
        $this->deleteFile->execute([$siteId, $path]);
    }

    public function clearFiles(int $siteId): void
    {
        $this->pdo->prepare('DELETE FROM files WHERE site_id = ?')->execute([$siteId]);
    }

    // ---- findings ----

    public function addFinding(int $siteId, Finding $f, int $now): int
    {
        $this->insertFinding ??= $this->pdo->prepare(<<<'SQL'
            INSERT INTO findings (site_id, path, kind, severity, rule, message, sha256, status, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            SQL);
        // Info-level changes (e.g. new images in uploads) are kept for the record but need no action.
        $status = $f->severity === Severity::Info ? 'info' : 'open';
        $this->insertFinding->execute([
            $siteId, $f->path, $f->kind, $f->severity->value, $f->rule, $f->message, $f->sha256, $status, $now,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /** @return array<int,array<string,mixed>> */
    public function openFindings(?int $siteId = null): array
    {
        $sql = "SELECT f.*, s.name AS site_name FROM findings f JOIN sites s ON s.id = f.site_id WHERE f.status = 'open'";
        $args = [];
        if ($siteId !== null) {
            $sql .= ' AND f.site_id = ?';
            $args[] = $siteId;
        }
        $sql .= " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, f.id";
        $st = $this->pdo->prepare($sql);
        $st->execute($args);
        return $st->fetchAll();
    }

    /** @param int[] $ids */
    public function ackFindings(array $ids, int $now): int
    {
        if ($ids === []) {
            return 0;
        }
        $in = implode(',', array_fill(0, count($ids), '?'));
        $st = $this->pdo->prepare("UPDATE findings SET status = 'acked', resolved_at = ? WHERE status = 'open' AND id IN ({$in})");
        $st->execute([$now, ...$ids]);
        return $st->rowCount();
    }

    public function ackAllFindings(?int $siteId, int $now): int
    {
        $sql = "UPDATE findings SET status = 'acked', resolved_at = ? WHERE status = 'open'";
        $args = [$now];
        if ($siteId !== null) {
            $sql .= ' AND site_id = ?';
            $args[] = $siteId;
        }
        $st = $this->pdo->prepare($sql);
        $st->execute($args);
        return $st->rowCount();
    }

    /**
     * Open findings of a site that have not reached Slack yet (including ones whose
     * delivery failed on an earlier run).
     *
     * @return Finding[]
     */
    public function pendingFindings(int $siteId, int $since): array
    {
        $st = $this->pdo->prepare(
            "SELECT * FROM findings WHERE site_id = ? AND status = 'open' AND notified_at IS NULL AND detected_at >= ? ORDER BY id"
        );
        $st->execute([$siteId, $since]);
        $out = [];
        foreach ($st->fetchAll() as $r) {
            $out[] = new Finding(
                $r['kind'], $r['path'], Severity::from($r['severity']), $r['rule'], $r['message'], $r['sha256'], (int) $r['id'],
            );
        }
        return $out;
    }

    /** @param int[] $ids */
    public function markFindingsNotified(array $ids, int $now): void
    {
        foreach (array_chunk($ids, 500) as $chunk) {
            $in = implode(',', array_fill(0, count($chunk), '?'));
            $this->pdo->prepare("UPDATE findings SET notified_at = ? WHERE id IN ({$in})")->execute([$now, ...$chunk]);
        }
    }

    // ---- notifications ----

    public function notifiedSince(string $fingerprint, int $since): bool
    {
        $st = $this->pdo->prepare('SELECT 1 FROM notifications WHERE fingerprint = ? AND sent_at >= ?');
        $st->execute([$fingerprint, $since]);
        return $st->fetchColumn() !== false;
    }

    public function markNotified(string $fingerprint, int $now): void
    {
        $st = $this->pdo->prepare(
            'INSERT INTO notifications (fingerprint, sent_at) VALUES (?, ?)
             ON CONFLICT (fingerprint) DO UPDATE SET sent_at = excluded.sent_at'
        );
        $st->execute([$fingerprint, $now]);
    }

    public function pruneNotifications(int $before): void
    {
        $this->pdo->prepare('DELETE FROM notifications WHERE sent_at < ?')->execute([$before]);
    }
}
