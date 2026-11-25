<?php

declare(strict_types=1);

namespace WPGuard;

/** Looks for known malicious code patterns in file contents. */
final class PatternScanner
{
    public const TARGET_PHP = 'php';
    public const TARGET_HTACCESS = 'htaccess';
    public const TARGET_UPLOADS = 'uploads';

    private const EXCERPT_LENGTH = 80;

    /** @var array<int,array{id:string,severity:Severity,targets:string[],description:string,regex:string}> */
    private array $rules = [];

    /** @param array<int,array<string,mixed>> $rules */
    public function __construct(array $rules, private int $maxBytes)
    {
        foreach ($rules as $i => $r) {
            foreach (['id', 'severity', 'targets', 'description', 'regex'] as $key) {
                if (!isset($r[$key])) {
                    throw new \RuntimeException("検出ルール #{$i} に {$key} がありません");
                }
            }
            if (@preg_match($r['regex'], '') === false) {
                throw new \RuntimeException("検出ルール {$r['id']} の正規表現が不正です");
            }
            $this->rules[] = [
                'id' => (string) $r['id'],
                'severity' => Severity::from((string) $r['severity']),
                'targets' => (array) $r['targets'],
                'description' => (string) $r['description'],
                'regex' => (string) $r['regex'],
            ];
        }
        // Most serious rules first, so the first match is the one worth reporting.
        usort($this->rules, static fn ($a, $b) => $b['severity']->rank() <=> $a['severity']->rank());
    }

    public static function fromFile(string $file, int $maxBytes): self
    {
        $rules = require $file;
        if (!is_array($rules)) {
            throw new \RuntimeException("検出ルールのファイルは配列を return する必要があります: {$file}");
        }
        return new self($rules, $maxBytes);
    }

    /** Which rule set applies to a path, or null when the file is not content-scanned. */
    public static function targetFor(string $rel): ?string
    {
        $base = basename($rel);
        if ($base === '.htaccess' || $base === '.user.ini') {
            return self::TARGET_HTACCESS;
        }
        if (Classifier::isExecutable($base)) {
            return self::TARGET_PHP;
        }
        if (str_starts_with($rel, 'wp-content/uploads/')) {
            return self::TARGET_UPLOADS;
        }
        return null;
    }

    public function scan(string $abs, string $target): ?PatternMatch
    {
        $size = @filesize($abs);
        if ($size === false || $size === 0) {
            return null;
        }
        $content = @file_get_contents($abs, false, null, 0, $this->maxBytes);
        if ($content === false) {
            return null;
        }
        foreach ($this->rules as $r) {
            if (!in_array($target, $r['targets'], true)) {
                continue;
            }
            $ok = @preg_match($r['regex'], $content, $m, PREG_OFFSET_CAPTURE);
            if ($ok === 1) {
                return new PatternMatch($r['id'], $r['severity'], $r['description'], self::excerpt($content, (int) $m[0][1]));
            }
        }
        return null;
    }

    private static function excerpt(string $content, int $offset): string
    {
        $s = substr($content, $offset, self::EXCERPT_LENGTH * 2);
        $s = preg_replace('/\s+/', ' ', $s) ?? '';
        $s = mb_strcut($s, 0, self::EXCERPT_LENGTH, 'UTF-8');
        return mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    }
}
