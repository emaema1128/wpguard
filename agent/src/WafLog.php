<?php

declare(strict_types=1);

namespace WPGuard;

/**
 * Reads ModSecurity's entries from the Apache error log and sums up the last 24 hours
 * for the daily digest: how many requests were blocked (or, in DetectionOnly mode,
 * would have been), on which sites, from where, and what kind of attack.
 *
 * One blocked request is one line with rule 949110 (the anomaly score check);
 * the rules that added to its score are separate lines with the same unique_id.
 */
final class WafLog
{
    private const MAX_READ = 64 * 1024 * 1024;
    /** Score totals and the "Host header is an IP address" note say nothing about the attack itself. */
    private const NOT_REASONS = ['949110', '980130', '959100', '980140', '920350'];

    private const CATEGORIES = [
        '941' => 'XSS',
        '942' => 'SQL インジェクション',
        '930' => 'ファイルの読み出し (パストラバーサル)',
        '931' => '外部ファイルの読み込み',
        '932' => 'コマンドの実行',
        '933' => 'PHP コードの注入',
        '934' => 'Node.js などへの攻撃',
        '943' => 'セッションの乗っ取り',
        '944' => 'Java への攻撃',
        '913' => '攻撃ツールによる調査',
        '920' => '不正な形式のリクエスト',
        '921' => '不正な形式のリクエスト',
    ];

    /** @param string[] $files newest first, e.g. error.log and error.log.1 */
    public function __construct(private array $files, private \DateTimeZone $logTimezone)
    {
    }

    /**
     * @return array{mode:string,blocked:int,hosts:array<string,int>,clients:array<string,int>,uris:array<string,int>,reasons:array<string,int>}|null
     *         null when no log file could be read
     */
    public function summarize(int $since, int $until): ?array
    {
        $read = false;
        $blocked = [];   // unique_id => [host, client, uri]
        $reasonsById = []; // unique_id => rule ids
        $denied = 0;
        $wouldBlock = 0;

        foreach ($this->files as $file) {
            $lines = $this->tail($file);
            if ($lines === null) {
                continue;
            }
            $read = true;
            foreach ($lines as $line) {
                if (!str_contains($line, 'ModSecurity: ') || !preg_match('/\[unique_id "([^"]+)"\]/', $line, $u)) {
                    continue;
                }
                $t = $this->time($line);
                if ($t === null || $t < $since || $t > $until) {
                    continue;
                }
                $uid = $u[1];
                preg_match('/\[id "(\d+)"\]/', $line, $id);
                $rule = $id[1] ?? '';

                if ($rule === '949110') {
                    $isDenied = str_contains($line, 'ModSecurity: Access denied');
                    $isDenied ? $denied++ : $wouldBlock++;
                    preg_match('/\[hostname "([^"]*)"\]/', $line, $h);
                    preg_match('/\[client ([0-9a-fA-F:.]+?)(?::\d+)?\]/', $line, $c);
                    preg_match('/\[uri "([^"]*)"\]/', $line, $p);
                    $blocked[$uid] = [$h[1] ?? '?', $c[1] ?? '?', $p[1] ?? '?'];
                } elseif ($rule !== '' && !in_array($rule, self::NOT_REASONS, true)) {
                    $reasonsById[$uid][$rule] = true;
                }
            }
        }
        if (!$read) {
            return null;
        }

        $hosts = $clients = $uris = $reasons = [];
        foreach ($blocked as $uid => [$host, $client, $uri]) {
            $hosts[$host] = ($hosts[$host] ?? 0) + 1;
            $clients[$client] = ($clients[$client] ?? 0) + 1;
            $uris[$uri] = ($uris[$uri] ?? 0) + 1;
            $cats = [];
            foreach (array_keys($reasonsById[$uid] ?? []) as $rule) {
                $cats[self::CATEGORIES[substr((string) $rule, 0, 3)] ?? 'そのほか'] = true;
            }
            foreach (array_keys($cats) as $cat) {
                $reasons[$cat] = ($reasons[$cat] ?? 0) + 1;
            }
        }
        foreach ([&$hosts, &$clients, &$uris, &$reasons] as &$list) {
            arsort($list);
        }
        unset($list);

        return [
            // Any real block means the engine is On; only warnings means DetectionOnly.
            'mode' => $denied > 0 || $wouldBlock === 0 ? 'block' : 'detect',
            'blocked' => count($blocked),
            'hosts' => $hosts,
            'clients' => $clients,
            'uris' => $uris,
            'reasons' => $reasons,
        ];
    }

    /** Apache writes its error log in the server's local time. */
    public static function systemTimezone(): \DateTimeZone
    {
        $link = @readlink('/etc/localtime');
        if (is_string($link) && preg_match('#zoneinfo/(.+)$#', $link, $m)) {
            try {
                return new \DateTimeZone($m[1]);
            } catch (\Exception) {
            }
        }
        $name = trim((string) @file_get_contents('/etc/timezone'));
        try {
            return new \DateTimeZone($name !== '' ? $name : 'UTC');
        } catch (\Exception) {
            return new \DateTimeZone('UTC');
        }
    }

    /** "[Thu Nov 26 02:47:05.622831 2026] ..." → Unix time */
    private function time(string $line): ?int
    {
        if (!preg_match('/^\[\w{3} (\w{3}) +(\d{1,2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]/', $line, $m)) {
            return null;
        }
        $d = \DateTimeImmutable::createFromFormat('M j H:i:s Y', "{$m[1]} {$m[2]} {$m[3]} {$m[4]}", $this->logTimezone);
        return $d === false ? null : $d->getTimestamp();
    }

    /** @return string[]|null the last part of the file (at most MAX_READ bytes) */
    private function tail(string $file): ?array
    {
        // Only regular files: in some containers error.log is a link to /dev/stderr, which never ends.
        if (!is_file($file)) {
            return null;
        }
        $size = @filesize($file);
        $h = $size === false ? false : @fopen($file, 'rb');
        if ($h === false) {
            return null;
        }
        if ($size > self::MAX_READ) {
            fseek($h, -self::MAX_READ, SEEK_END);
            fgets($h); // skip the partial first line
        }
        $lines = [];
        while (($line = fgets($h)) !== false) {
            $lines[] = $line;
        }
        fclose($h);
        return $lines;
    }
}
