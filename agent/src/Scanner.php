<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Compares a site's files with the stored baseline.
 *
 * Quick scan: a file is re-hashed only when size, mtime, ctime or inode changed.
 * ctime cannot be set from userland, so "touch -r" tricks to restore mtime are still caught.
 * Full scan: every file is re-hashed.
 */
final class Scanner
{
    private const COMMIT_EVERY = 2000;

    /** @param string[] $excludes */
    public function __construct(
        private Database $db,
        private Hasher $hasher,
        private Classifier $classifier,
        private array $excludes,
    ) {
    }

    /**
     * @param bool     $baselineOnly record the current state without producing findings
     * @param string[] $skipDirs     absolute paths of nested installs to leave to their own scan
     */
    public function scan(Site $site, bool $full, bool $baselineOnly, array $skipDirs, int $now): ScanResult
    {
        $start = microtime(true);
        $result = new ScanResult();
        $result->baseline = $baselineOnly;
        $old = $this->db->files($site->id);
        $walker = new FileWalker($this->excludes, $skipDirs);
        $pending = 0;

        $this->db->begin();
        try {
            foreach ($walker->walk($site->path) as $rel => $stat) {
                $result->files++;
                $abs = $site->path . '/' . $rel;
                $prev = $old[$rel] ?? null;
                unset($old[$rel]);

                if ($prev === null) {
                    $hash = $this->hasher->hash($abs, $stat);
                    $result->hashed++;
                    $this->db->upsertFile($site->id, $rel, $stat, $hash);
                    if (!$baselineOnly) {
                        $this->record($site, $result, Finding::ADDED, $rel, $stat['type'], $hash, $now);
                    }
                    $pending++;
                } else {
                    $metaChanged = $prev['type'] !== $stat['type']
                        || (int) $prev['size'] !== $stat['size']
                        || (int) $prev['mtime'] !== $stat['mtime']
                        || (int) $prev['ctime'] !== $stat['ctime']
                        || (int) $prev['inode'] !== $stat['inode'];

                    if ($metaChanged || $full) {
                        $hash = $this->hasher->hash($abs, $stat);
                        $result->hashed++;
                        $contentChanged = ($hash === null || $prev['sha256'] === null)
                            ? ($prev['type'] !== $stat['type'] || (int) $prev['size'] !== $stat['size'] || (int) $prev['mtime'] !== $stat['mtime'])
                            : $hash !== $prev['sha256'];
                        if ($metaChanged || $contentChanged) {
                            $this->db->upsertFile($site->id, $rel, $stat, $hash);
                            $pending++;
                        }
                        if ($contentChanged && !$baselineOnly) {
                            $this->record($site, $result, Finding::MODIFIED, $rel, $stat['type'], $hash, $now);
                        }
                    }
                }

                if ($pending >= self::COMMIT_EVERY) {
                    $this->db->commit();
                    $this->db->begin();
                    $pending = 0;
                }
            }

            foreach ($old as $rel => $prev) {
                $this->db->deleteFile($site->id, $rel);
                if (!$baselineOnly) {
                    $this->record($site, $result, Finding::DELETED, $rel, $prev['type'], $prev['sha256'], $now);
                }
            }

            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }

        $result->errors = $walker->errors;
        $result->seconds = microtime(true) - $start;
        return $result;
    }

    private function record(Site $site, ScanResult $result, string $kind, string $rel, string $type, ?string $hash, int $now): void
    {
        $f = $this->classifier->classify($kind, $rel, $type, $hash);
        $f->id = $this->db->addFinding($site->id, $f, $now);
        $result->findings[] = $f;
    }
}
