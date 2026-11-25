<?php

declare(strict_types=1);

namespace WPGuard\Checksums;

/** Used when checksum verification is disabled. */
final class NullChecksums implements ChecksumProvider
{
    public function core(string $version, string $locale): ?array
    {
        return null;
    }

    public function plugin(string $slug, string $version): ?array
    {
        return null;
    }
}
