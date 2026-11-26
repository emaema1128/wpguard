<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Compares a site's files with the stored baseline.
 *
 * Quick scan: a file is re-hashed only when size, mtime, ctime or inode changed.
 * ctime cannot be set from userland, so "touch -r" tricks to restore mtime are still caught.
 * Full scan: every file is re-hashed, and unchanged files are audited again
 * (malware patterns, official checksums) so that new rules catch old files.
 * Baseline: nothing is reported as changed, but every file is audited, so malware
 * that was already there when monitoring started is not silently accepted.
 *
 * Timestamps only have one-second resolution, so a file rewritten in the same second
 * as it was recorded (same size) would look unchanged. Like git's "racy" index entries,
 * such fresh files are stored with ctime 0, which forces a re-hash on the next scan.
 */
final class Scanner
{
    private const COMMIT_EVERY = 2000;

    /** @param string[] $excludes */
    public function __construct(
        private Database $db,
        private Hasher $hasher,
        private Classifier $classifier,
        private PatternScanner $patterns,
        private OfficialVerifier $verifier,
        private array $excludes,
    ) {
    }

    /**
     * @param bool     $baselineOnly record the current state without reporting changes
     * @param string[] $skipDirs     absolute paths of nested installs to leave to their own scan
     */
    public function scan(Site $site, bool $full, bool $baselineOnly, array $skipDirs, int $now): ScanResult
    {
        $start = microtime(true);
        $result = new ScanResult();
        $result->baseline = $baselineOnly;
        $old = $this->db->files($site->id);
        $walker = new FileWalker($this->excludes, $skipDirs);
        $this->verifier->forSite($site);
        $racyFrom = (int) floor($start) - 1;
        $pending = 0;

        $this->db->begin();
        try {
            foreach ($walker->walk($site->path) as $rel => $stat) {
                $result->files++;
                $record = $stat;
                if ($stat['mtime'] >= $racyFrom || $stat['ctime'] >= $racyFrom) {
                    $record['ctime'] = 0;
                }
                $abs = $site->path . '/' . $rel;
                $prev = $old[$rel] ?? null;
                unset($old[$rel]);

                if ($prev === null) {
                    $hash = $this->hasher->hash($abs, $stat);
                    $result->hashed++;
                    $this->db->upsertFile($site->id, $rel, $record, $hash);
                    $pending++;
                    if ($baselineOnly) {
                        $this->audit($site, $result, $rel, $abs, $stat['type'], $hash, $now);
                    } else {
                        $this->report($site, $result, Finding::ADDED, $rel, $abs, $stat['type'], $hash, $now);
                    }
                } else {
                    $metaChanged = $prev['type'] !== $stat['type']
                        || (int) $prev['size'] !== $stat['size']
                        || (int) $prev['mtime'] !== $stat['mtime']
                        || (int) $prev['ctime'] !== $stat['ctime']
                        || (int) $prev['inode'] !== $stat['inode'];

                    if ($metaChanged || $full || $baselineOnly) {
                        $hash = $this->hasher->hash($abs, $stat);
                        $result->hashed++;
                        $contentChanged = ($hash === null || $prev['sha256'] === null)
                            ? ($prev['type'] !== $stat['type'] || (int) $prev['size'] !== $stat['size'] || (int) $prev['mtime'] !== $stat['mtime'])
                            : $hash !== $prev['sha256'];
                        if ($metaChanged || $contentChanged) {
                            $this->db->upsertFile($site->id, $rel, $record, $hash);
                            $pending++;
                        }
                        if ($contentChanged && !$baselineOnly) {
                            $this->report($site, $result, Finding::MODIFIED, $rel, $abs, $stat['type'], $hash, $now);
                        } elseif ($full || $baselineOnly) {
                            $this->audit($site, $result, $rel, $abs, $stat['type'], $hash, $now);
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
                    $f = $this->classifier->classify(Finding::DELETED, $rel, $prev['type'], $prev['sha256']);
                    $this->store($site, $result, $f, $now);
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

    /** A file was added or changed: always record it, with whatever the content checks found. */
    private function report(Site $site, ScanResult $result, string $kind, string $rel, string $abs, string $type, ?string $hash, int $now): void
    {
        [$match, $official] = $this->inspect($rel, $abs, $type, $hash);
        if ($official === OfficialVerifier::MATCH && $match === null) {
            // The file is back to the official contents (e.g. a cleaned or reinstalled file): earlier alerts about it are settled.
            $this->db->setFindingStatus((int) $site->id, $rel, 'acked', $now);
        }
        $this->store($site, $result, $this->classifier->classify($kind, $rel, $type, $hash, $match, $official), $now);
    }

    /** An unchanged file: record it only if it looks malicious, and only once. */
    private function audit(Site $site, ScanResult $result, string $rel, string $abs, string $type, ?string $hash, int $now): void
    {
        [$match, $official] = $this->inspect($rel, $abs, $type, $hash);
        $f = $this->classifier->classify(Finding::EXISTING, $rel, $type, $hash, $match, $official);
        if ($f->severity === Severity::Info || $this->db->hasFinding((int) $site->id, $rel, $hash, $f->rule)) {
            return;
        }
        $this->store($site, $result, $f, $now);
    }

    /** @return array{?PatternMatch,?string} */
    private function inspect(string $rel, string $abs, string $type, ?string $hash): array
    {
        if ($type === FileWalker::TYPE_LINK) {
            return [null, null];
        }
        $official = $this->verifier->verify($rel, $abs, $hash);
        if ($official === OfficialVerifier::MATCH) {
            // Identical to the official release: do not second-guess it with patterns.
            return [null, $official];
        }
        $target = PatternScanner::targetFor($rel);
        return [$target === null ? null : $this->patterns->scan($abs, $target), $official];
    }

    private function store(Site $site, ScanResult $result, Finding $f, int $now): void
    {
        $f->id = $this->db->addFinding((int) $site->id, $f, $now);
        $result->findings[] = $f;
    }
}
