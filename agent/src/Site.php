<?php

declare(strict_types=1);

namespace WPGuard;

final class Site
{
    public function __construct(
        public readonly string $path,
        public readonly string $name,
        public readonly ?string $wpVersion,
        public ?int $id = null,
    ) {
    }
}
