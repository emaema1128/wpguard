<?php

declare(strict_types=1);

namespace WPGuard;

use WPGuard\Notifier\Message;
use WPGuard\Notifier\Notifier;

/**
 * Turns findings into Slack messages: filters by severity, drops duplicates,
 * and collapses large batches (e.g. a plugin update) into one summary.
 */
final class NotificationService
{
    private const SHOW_IN_SUMMARY = 10;
    /** Findings that could not be delivered are retried on later runs for this long. */
    private const RETRY_SECONDS = 86400;

    public function __construct(
        private Notifier $notifier,
        private Database $db,
        private Config $config,
        private Logger $logger,
    ) {
    }

    /** Sends every open finding of the site that has not been delivered yet. */
    public function notifyPending(Site $site, int $now): void
    {
        $min = Severity::from((string) $this->config->get('notify_min_severity'));
        $since = $now - (int) $this->config->get('dedupe_hours') * 3600;

        $toSend = [];
        $skipped = [];
        foreach ($this->db->pendingFindings((int) $site->id, $now - self::RETRY_SECONDS) as $f) {
            if ($f->severity->atLeast($min) && !$this->db->notifiedSince($f->fingerprint($site), $since)) {
                $toSend[] = $f;
            } else {
                $skipped[] = (int) $f->id;
            }
        }
        $this->db->markFindingsNotified($skipped, $now);
        if ($toSend === []) {
            return;
        }

        usort($toSend, static fn (Finding $a, Finding $b) => [$b->severity->rank(), $a->id] <=> [$a->severity->rank(), $b->id]);
        $severity = Severity::max(array_map(static fn (Finding $f) => $f->severity, $toSend));
        $threshold = (int) $this->config->get('aggregate_threshold');
        $text = count($toSend) > $threshold
            ? $this->summaryText($site, $toSend, $severity, $now)
            : $this->detailText($site, $toSend, $severity, $now);

        if ($this->notifier->send(new Message($severity, $text))) {
            foreach ($toSend as $f) {
                $this->db->markNotified($f->fingerprint($site), $now);
            }
            $this->db->markFindingsNotified(array_map(static fn (Finding $f) => (int) $f->id, $toSend), $now);
        } else {
            $this->logger->error("Slack 通知に失敗しました: {$site->name} (" . count($toSend) . ' 件、次回のスキャンで再送します)');
        }
    }

    public function notifyEvent(Severity $severity, string $siteName, string $title, string $body = ''): bool
    {
        $text = $this->header($severity, $siteName) . "\n*" . self::esc($title) . '*';
        if ($body !== '') {
            $text .= "\n" . $body;
        }
        $ok = $this->notifier->send(new Message($severity, $text));
        if (!$ok) {
            $this->logger->error("Slack 通知に失敗しました: {$siteName} / {$title}");
        }
        return $ok;
    }

    /** @param Finding[] $findings */
    private function detailText(Site $site, array $findings, Severity $severity, int $now): string
    {
        $lines = [$this->header($severity, $site->name, count($findings) > 1 ? count($findings) . ' 件の検知' : '')];
        foreach ($findings as $f) {
            $lines[] = sprintf('%s *%s*', $f->severity->emoji(), self::esc($f->message));
            $lines[] = sprintf('      📄 `%s`  (#%d)', self::code($f->path), $f->id);
            if ($f->detail !== null && $f->detail !== '') {
                $lines[] = sprintf('      🔍 `%s`', self::code($f->detail));
            }
        }
        $lines[] = sprintf('🕐 %s', date('Y-m-d H:i', $now));
        $lines[] = $this->footer($site, $findings);
        return implode("\n", $lines);
    }

    /** @param Finding[] $findings */
    private function summaryText(Site $site, array $findings, Severity $severity, int $now): string
    {
        $lines = [$this->header($severity, $site->name, count($findings) . ' 件の変更をまとめて通知します')];

        $groups = [];
        foreach ($findings as $f) {
            $key = $f->severity->value . "\0" . $f->message;
            $groups[$key] ??= ['severity' => $f->severity, 'message' => $f->message, 'count' => 0];
            $groups[$key]['count']++;
        }
        foreach ($groups as $g) {
            $lines[] = sprintf('%s %s: %d 件', $g['severity']->emoji(), self::esc($g['message']), $g['count']);
        }

        $lines[] = '';
        $lines[] = '*主なファイル*';
        foreach (array_slice($findings, 0, self::SHOW_IN_SUMMARY) as $f) {
            $lines[] = sprintf('%s `%s`  (#%d)', $f->severity->emoji(), self::code($f->path), $f->id);
        }
        $rest = count($findings) - self::SHOW_IN_SUMMARY;
        if ($rest > 0) {
            $lines[] = "…ほか {$rest} 件";
        }
        $lines[] = sprintf('🕐 %s', date('Y-m-d H:i', $now));
        $lines[] = $this->footer($site, $findings);
        return implode("\n", $lines);
    }

    private function header(Severity $severity, string $siteName, string $suffix = ''): string
    {
        $h = sprintf('%s *[%s] %s*', $severity->emoji(), $severity->label(), self::esc($siteName));
        if ($suffix !== '') {
            $h .= ' — ' . $suffix;
        }
        $mention = (string) $this->config->slack('mention_critical');
        if ($severity === Severity::Critical && $mention !== '') {
            $h .= ' ' . $mention;
        }
        return $h;
    }

    /** @param Finding[] $findings */
    private function footer(Site $site, array $findings): string
    {
        $site = self::code($site->name);
        if (count($findings) === 1) {
            $f = $findings[0];
            if (self::canQuarantine($f)) {
                return sprintf('👉 取り除く: `wpguard quarantine %d`  /  問題なければ: `wpguard ack %d`', $f->id, $f->id);
            }
            return sprintf('👉 確認したら: `wpguard ack %d`', $f->id);
        }
        $hint = array_filter($findings, [self::class, 'canQuarantine']) !== [] ? '  /  取り除く: `wpguard quarantine <ID>`' : '';
        return sprintf('👉 一覧: `wpguard findings --site=%s`%s  /  確認したら: `wpguard ack --site=%s --all`', $site, $hint, $site);
    }

    /** Suggest quarantine only for serious findings where removing the file does not break the site. */
    private static function canQuarantine(Finding $f): bool
    {
        return $f->severity === Severity::Critical && $f->kind !== Finding::DELETED && Quarantine::breaksSite($f->path) === null;
    }

    /** Escapes Slack control characters so file names cannot inject mentions or links. */
    private static function esc(string $s): string
    {
        return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $s);
    }

    private static function code(string $s): string
    {
        return self::esc(str_replace(['`', "\n", "\r"], ["'", ' ', ' '], $s));
    }
}
