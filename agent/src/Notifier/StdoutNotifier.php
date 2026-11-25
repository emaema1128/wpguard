<?php

declare(strict_types=1);

namespace WPGuard\Notifier;

/** Prints messages instead of sending them (--dry-run, or no webhook configured). */
final class StdoutNotifier implements Notifier
{
    public function send(Message $message): bool
    {
        fwrite(STDOUT, "----- Slack 通知 (送信せず表示のみ) -----\n{$message->text}\n\n");
        return true;
    }
}
