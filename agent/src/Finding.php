<?php

declare(strict_types=1);

namespace WPGuard;

final class Finding
{
    public const ADDED = 'added';
    public const MODIFIED = 'modified';
    public const DELETED = 'deleted';
    /** Already present when the baseline was taken, or found by a full scan without a change. */
    public const EXISTING = 'existing';

    public function __construct(
        public readonly string $kind,
        public readonly string $path,
        public readonly Severity $severity,
        public readonly string $rule,
        public readonly string $message,
        public readonly ?string $sha256,
        public readonly ?string $detail = null,
        public ?int $id = null,
    ) {
    }

    public function fingerprint(Site $site): string
    {
        return sha1(implode("\0", [$site->path, $this->kind, $this->path, $this->sha256 ?? '']));
    }
}
