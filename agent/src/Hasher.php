<?php

declare(strict_types=1);

namespace WPGuard;

final class Hasher
{
    public function __construct(private int $maxBytes)
    {
    }

    /**
     * Returns null when the file is too large or unreadable; the scanner then
     * relies on size/mtime/ctime/inode alone.
     *
     * @param array{type:string,size:int} $stat
     */
    public function hash(string $abs, array $stat): ?string
    {
        if ($stat['type'] === FileWalker::TYPE_LINK) {
            $target = @readlink($abs);
            return $target === false ? null : 'link:' . hash('sha256', $target);
        }
        if ($stat['size'] > $this->maxBytes) {
            return null;
        }
        $h = @hash_file('sha256', $abs);
        return $h === false ? null : $h;
    }
}
