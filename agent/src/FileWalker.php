<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Walks a site's files without following symlinks (an attacker could point a
 * link at / and make the scan crawl the whole server).
 */
final class FileWalker
{
    public const TYPE_FILE = 'f';
    public const TYPE_LINK = 'l';

    /** @var string[] */
    public array $errors = [];

    /**
     * @param string[] $excludes  fnmatch patterns relative to the site root
     * @param string[] $skipDirs  absolute paths to skip (nested WordPress installs)
     */
    public function __construct(private array $excludes, private array $skipDirs)
    {
    }

    /** @return \Generator<string, array{type:string,size:int,mtime:int,ctime:int,inode:int}> */
    public function walk(string $root): \Generator
    {
        yield from $this->walkDir($root, '');
    }

    private function walkDir(string $abs, string $rel): \Generator
    {
        $h = @opendir($abs);
        if ($h === false) {
            $this->errors[] = "ディレクトリを読めません: {$abs}";
            return;
        }
        $entries = [];
        while (($e = readdir($h)) !== false) {
            if ($e !== '.' && $e !== '..') {
                $entries[] = $e;
            }
        }
        closedir($h);
        sort($entries, SORT_STRING);

        foreach ($entries as $e) {
            $childRel = $rel === '' ? $e : "{$rel}/{$e}";
            $childAbs = "{$abs}/{$e}";
            $st = @lstat($childAbs);
            if ($st === false) {
                continue;
            }
            $kind = $st['mode'] & 0170000;
            if ($kind === 0040000) {
                if (in_array($childAbs, $this->skipDirs, true) || $this->isExcluded("{$childRel}/")) {
                    continue;
                }
                yield from $this->walkDir($childAbs, $childRel);
            } elseif ($kind === 0100000 || $kind === 0120000) {
                if ($this->isExcluded($childRel)) {
                    continue;
                }
                yield $childRel => [
                    'type' => $kind === 0120000 ? self::TYPE_LINK : self::TYPE_FILE,
                    'size' => (int) $st['size'],
                    'mtime' => (int) $st['mtime'],
                    'ctime' => (int) $st['ctime'],
                    'inode' => (int) $st['ino'],
                ];
            }
        }
    }

    private function isExcluded(string $rel): bool
    {
        foreach ($this->excludes as $pattern) {
            if (fnmatch($pattern, $rel)) {
                return true;
            }
        }
        return false;
    }
}
