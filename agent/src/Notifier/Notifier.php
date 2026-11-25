<?php

declare(strict_types=1);

namespace WPGuard\Notifier;

interface Notifier
{
    /** Returns true when the message was delivered. */
    public function send(Message $message): bool;
}
