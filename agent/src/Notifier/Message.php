<?php

declare(strict_types=1);

namespace WPGuard\Notifier;

use WPGuard\Severity;

final class Message
{
    public function __construct(
        public readonly Severity $severity,
        public readonly string $text,
    ) {
    }
}
