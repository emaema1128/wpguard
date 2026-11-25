<?php

declare(strict_types=1);

namespace WPGuard;

final class PatternMatch
{
    public function __construct(
        public readonly string $rule,
        public readonly Severity $severity,
        public readonly string $description,
        public readonly string $excerpt,
    ) {
    }
}
