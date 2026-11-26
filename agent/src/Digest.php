<?php

declare(strict_types=1);

namespace WPGuard;

use WPGuard\Notifier\Message;

/**
 * N-04: one daily message about every site.
 *
 * Sites without problems are only counted, so the message stays short with many sites.
 * It also works as a heartbeat: if the morning digest does not arrive, the agent is down.
 */
final class Digest
{
    public function __construct(private Database $db, private Config $config)
    {
    }

    public function build(int $now): Message
    {
        $since = $now - 86400;
        $staleBefore = $now - (int) $this->config->get('stale_hours') * 3600;
        $sites = $this->db->sites();
        $recent = $this->db->findingCountsSince($since);
        $open = $this->db->openFindingCounts();
        $quarantine = $this->db->quarantineCounts($since);

        $totalRecent = ['critical' => 0, 'warning' => 0, 'info' => 0];
        $totalOpen = ['critical' => 0, 'warning' => 0];
        $problems = [];
        $okCount = 0;
        $active = 0;

        foreach ($sites as $s) {
            $id = (int) $s['id'];
            $r = $recent[$id] ?? [];
            $o = $open[$id] ?? [];
            foreach ($totalRecent as $k => $_) {
                $totalRecent[$k] += $r[$k] ?? 0;
            }
            foreach ($totalOpen as $k => $_) {
                $totalOpen[$k] += $o[$k] ?? 0;
            }

            $notes = [];
            if ($s['missing_since'] !== null) {
                $notes[] = sprintf('⚠️ %s から見つかりません', date('m/d H:i', (int) $s['missing_since']));
            } else {
                $active++;
                if ($s['last_scan'] === null || (int) $s['last_scan'] < $staleBefore) {
                    $notes[] = $s['last_scan'] === null
                        ? '⚠️ まだスキャンされていません'
                        : sprintf('⚠️ 最後のスキャンが %s です (止まっている可能性)', self::ago($now - (int) $s['last_scan']));
                }
            }
            $openTotal = ($o['critical'] ?? 0) + ($o['warning'] ?? 0);
            if ($openTotal > 0) {
                $notes[] = sprintf('未対応 %s', self::counts($o));
            }
            if (($r['critical'] ?? 0) + ($r['warning'] ?? 0) > 0) {
                $notes[] = sprintf('24 時間の検知 %s', self::counts($r));
            }

            if ($notes === []) {
                $okCount++;
            } else {
                $rank = ($o['critical'] ?? 0) > 0 ? 0 : (str_contains(implode('', $notes), '⚠️') ? 1 : 2);
                $problems[] = [$rank, (string) $s['name'], $notes];
            }
        }
        usort($problems, static fn ($a, $b) => [$a[0], $a[1]] <=> [$b[0], $b[1]]);

        $severity = $problems === [] ? Severity::Info : (($totalOpen['critical'] > 0) ? Severity::Critical : Severity::Warning);
        $head = $problems === [] ? '✅' : ($severity === Severity::Critical ? '🔴' : '🟡');
        $lines = [sprintf('%s *[日次サマリー] WPGuard* — 監視中 %d サイト', $head, $active)];

        if ($problems === []) {
            $lines[] = '異常はありません。';
        } else {
            $lines[] = sprintf('未対応の検知: %s', self::counts($totalOpen, true));
            $lines[] = '';
            $lines[] = '*確認が必要なサイト*';
            foreach ($problems as [, $name, $notes]) {
                $lines[] = sprintf('• *%s*: %s', self::esc($name), implode(' / ', $notes));
            }
            $lines[] = '';
            $lines[] = sprintf('異常のないサイト: %d', $okCount);
        }
        $lines[] = sprintf(
            '過去 24 時間: 検知 %s、記録のみ 🔵%d 件、隔離 %d 件 (保管中 %d 件)',
            self::counts($totalRecent, true), $totalRecent['info'], $quarantine['recent'], $quarantine['held'],
        );
        if ($totalOpen['critical'] + $totalOpen['warning'] > 0) {
            $lines[] = '👉 一覧: `wpguard findings`';
        }
        $lines[] = sprintf('🕐 %s', date('Y-m-d H:i', $now));

        return new Message($severity, implode("\n", $lines));
    }

    /** @param array<string,int> $c */
    private static function counts(array $c, bool $showZero = false): string
    {
        $parts = [];
        foreach (['critical' => '🔴', 'warning' => '🟡'] as $k => $emoji) {
            $n = $c[$k] ?? 0;
            if ($n > 0 || $showZero) {
                $parts[] = "{$emoji}{$n}";
            }
        }
        return implode(' ', $parts);
    }

    private static function ago(int $seconds): string
    {
        return $seconds >= 86400 ? sprintf('%d 日前', intdiv($seconds, 86400)) : sprintf('%d 時間前', intdiv($seconds, 3600));
    }

    private static function esc(string $s): string
    {
        return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $s);
    }
}
