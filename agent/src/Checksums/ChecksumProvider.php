<?php

declare(strict_types=1);

namespace WPGuard\Checksums;

interface ChecksumProvider
{
    /**
     * Official checksums of a WordPress release.
     *
     * @return array<string,string>|null relative path => md5, or null when unavailable
     */
    public function core(string $version, string $locale): ?array;

    /**
     * Official checksums of a plugin release from the wordpress.org plugin directory.
     *
     * @return array<string,string[]>|null path inside the plugin => accepted sha256 values,
     *                                     or null when the plugin is not in the directory / unavailable
     */
    public function plugin(string $slug, string $version): ?array;
}
