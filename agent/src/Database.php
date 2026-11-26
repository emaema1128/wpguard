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
        if ($version < 2) {
            $this->pdo->exec(<<<'SQL'
                ALTER TABLE findings ADD COLUMN detail TEXT;
                CREATE INDEX findings_path ON findings (site_id, path);
                CREATE TABLE checksum_cache (
                    key TEXT PRIMARY KEY,
                    body TEXT,
                    fetched_at INTEGER NOT NULL
                ) WITHOUT ROWID;
                PRAGMA user_version = 2;
                SQL);
        }
        if ($version < 3) {
            $this->pdo->exec(<<<'SQL'
                CREATE TABLE quarantine (
                    id INTEGER PRIMARY KEY,
                    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                    finding_id INTEGER,
                    path TEXT NOT NULL,
                    stored TEXT,
                    sha256 TEXT,
                    size INTEGER NOT NULL,
                    mode INTEGER NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    mtime INTEGER NOT NULL,
                    is_link INTEGER NOT NULL DEFAULT 0,
                    quarantined_at INTEGER NOT NULL,
                    restored_at INTEGER,
                    purged_at INTEGER
                );
                PRAGMA user_version = 3;
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
            INSERT INTO findings (site_id, path, kind, severity, rule, message, sha256, detail, status, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            SQL);
        // Info-level changes (e.g. new images in uploads) are kept for the record but need no action.
        $status = $f->severity === Severity::Info ? 'info' : 'open';
        $this->insertFinding->execute([
            $siteId, $f->path, $f->kind, $f->severity->value, $f->rule, $f->message, $f->sha256, $f->detail, $status, $now,
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
                $r['kind'], $r['path'], Severity::from($r['severity']), $r['rule'], $r['message'], $r['sha256'], $r['detail'], (int) $r['id'],
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

    /** Whether this exact problem (same file contents, same rule) was already recorded, in any status. */
    public function hasFinding(int $siteId, string $path, ?string $sha256, string $rule): bool
    {
        $st = $this->pdo->prepare('SELECT 1 FROM findings WHERE site_id = ? AND path = ? AND sha256 IS ? AND rule = ? LIMIT 1');
        $st->execute([$siteId, $path, $sha256, $rule]);
        return $st->fetchColumn() !== false;
    }

    /** @return array<string,mixed>|null the finding with its site's path and name */
    public function finding(int $id): ?array
    {
        $st = $this->pdo->prepare('SELECT f.*, s.path AS site_path, s.name AS site_name FROM findings f JOIN sites s ON s.id = f.site_id WHERE f.id = ?');
        $st->execute([$id]);
        $row = $st->fetch();
        return $row === false ? null : $row;
    }

    /** Changes the status of every finding of one file (e.g. after quarantine). */
    public function setFindingStatus(int $siteId, string $path, string $status, int $now, string $from = 'open'): void
    {
        $st = $this->pdo->prepare('UPDATE findings SET status = ?, resolved_at = ? WHERE site_id = ? AND path = ? AND status = ?');
        $st->execute([$status, $now, $siteId, $path, $from]);
    }

    /** @return array<int,array<string,int>> site id => severity => count, for findings since a time */
    public function findingCountsSince(int $since): array
    {
        $st = $this->pdo->prepare('SELECT site_id, severity, COUNT(*) AS n FROM findings WHERE detected_at >= ? GROUP BY site_id, severity');
        $st->execute([$since]);
        return self::bySiteSeverity($st->fetchAll());
    }

    /** @return array<int,array<string,int>> site id => severity => count, for open findings */
    public function openFindingCounts(): array
    {
        $rows = $this->pdo->query("SELECT site_id, severity, COUNT(*) AS n FROM findings WHERE status = 'open' GROUP BY site_id, severity")->fetchAll();
        return self::bySiteSeverity($rows);
    }

    /** @return array<int,array<string,int>> */
    private static function bySiteSeverity(array $rows): array
    {
        $out = [];
        foreach ($rows as $r) {
            $out[(int) $r['site_id']][$r['severity']] = (int) $r['n'];
        }
        return $out;
    }

    // ---- quarantine ----

    /** @return array{recent:int,held:int} */
    public function quarantineCounts(int $since): array
    {
        $st = $this->pdo->prepare('SELECT
            SUM(CASE WHEN quarantined_at >= ? THEN 1 ELSE 0 END) AS recent,
            SUM(CASE WHEN restored_at IS NULL AND purged_at IS NULL THEN 1 ELSE 0 END) AS held
            FROM quarantine');
        $st->execute([$since]);
        $r = $st->fetch();
        return ['recent' => (int) ($r['recent'] ?? 0), 'held' => (int) ($r['held'] ?? 0)];
    }

    /** @param array<string,mixed> $row */
    public function insertQuarantine(array $row): int
    {
        $cols = implode(', ', array_keys($row));
        $marks = implode(', ', array_fill(0, count($row), '?'));
        $this->pdo->prepare("INSERT INTO quarantine ({$cols}) VALUES ({$marks})")->execute(array_values($row));
        return (int) $this->pdo->lastInsertId();
    }

    /** @param array<string,mixed> $fields */
    public function updateQuarantine(int $id, array $fields): void
    {
        $set = implode(', ', array_map(static fn ($k) => "{$k} = ?", array_keys($fields)));
        $this->pdo->prepare("UPDATE quarantine SET {$set} WHERE id = ?")->execute([...array_values($fields), $id]);
    }

    public function deleteQuarantine(int $id): void
    {
        $this->pdo->prepare('DELETE FROM quarantine WHERE id = ?')->execute([$id]);
    }

    /** @return array<string,mixed>|null */
    public function quarantineEntry(int $id): ?array
    {
        $st = $this->pdo->prepare('SELECT q.*, s.path AS site_path, s.name AS site_name FROM quarantine q JOIN sites s ON s.id = q.site_id WHERE q.id = ?');
        $st->execute([$id]);
        $row = $st->fetch();
        return $row === false ? null : $row;
    }

    /** @return array<int,array<string,mixed>> newest first */
    public function quarantineEntries(): array
    {
        return $this->pdo->query('SELECT q.*, s.path AS site_path, s.name AS site_name FROM quarantine q JOIN sites s ON s.id = q.site_id ORDER BY q.id DESC')->fetchAll();
    }

    // ---- checksum cache ----

    /** @return array{body:?string,fetched_at:int}|null */
    public function cacheGet(string $key): ?array
    {
        $st = $this->pdo->prepare('SELECT body, fetched_at FROM checksum_cache WHERE key = ?');
        $st->execute([$key]);
        $row = $st->fetch();
        return $row === false ? null : ['body' => $row['body'], 'fetched_at' => (int) $row['fetched_at']];
    }

    public function cachePut(string $key, ?string $body, int $now): void
    {
        $st = $this->pdo->prepare(
            'INSERT INTO checksum_cache (key, body, fetched_at) VALUES (?, ?, ?)
             ON CONFLICT (key) DO UPDATE SET body = excluded.body, fetched_at = excluded.fetched_at'
        );
        $st->execute([$key, $body, $now]);
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
