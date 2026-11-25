<?php

declare(strict_types=1);

namespace WPGuard;

final class ScanResult
{
    /** @var Finding[] */
    public array $findings = [];
    public int $files = 0;
    public int $hashed = 0;
    public bool $baseline = false;
    /** @var string[] */
    public array $errors = [];
    public float $seconds = 0.0;

    /** @return array<string,int> severity value => count */
    public function counts(): array
    {
        $c = ['critical' => 0, 'warning' => 0, 'info' => 0];
        foreach ($this->findings as $f) {
            $c[$f->severity->value]++;
        }
        return $c;
    }
}
