<?php

declare(strict_types=1);

namespace WPGuard;

enum Severity: string
{
    case Critical = 'critical';
    case Warning = 'warning';
    case Info = 'info';

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 3,
            self::Warning => 2,
            self::Info => 1,
        };
    }

    public function emoji(): string
    {
        return match ($this) {
            self::Critical => '🔴',
            self::Warning => '🟡',
            self::Info => '🔵',
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Critical => '緊急',
            self::Warning => '警告',
            self::Info => '情報',
        };
    }

    public function atLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    /** @param Severity[] $list */
    public static function max(array $list): self
    {
        $max = self::Info;
        foreach ($list as $s) {
            if ($s->rank() > $max->rank()) {
                $max = $s;
            }
        }
        return $max;
    }
}
