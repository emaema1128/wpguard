<?php

declare(strict_types=1);

namespace WPGuard\Notifier;

use WPGuard\Logger;

/** Posts to Slack Incoming Webhooks. */
final class SlackNotifier implements Notifier
{
    private const MAX_ATTEMPTS = 3;

    /** @param array<string,string> $webhooksBySeverity */
    public function __construct(
        private string $defaultWebhook,
        private array $webhooksBySeverity,
        private int $timeout,
        private Logger $logger,
    ) {
        if (!extension_loaded('curl')) {
            throw new \RuntimeException('Slack 通知には PHP の curl 拡張モジュールが必要です');
        }
    }

    public function send(Message $message): bool
    {
        $url = $this->webhooksBySeverity[$message->severity->value] ?? $this->defaultWebhook;
        if ($url === '') {
            $this->logger->error('Slack の Webhook URL が設定されていません');
            return false;
        }
        $payload = json_encode(
            ['text' => $message->text, 'unfurl_links' => false, 'unfurl_media' => false],
            JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
        );

        for ($attempt = 1; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json; charset=utf-8'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_CONNECTTIMEOUT => $this->timeout,
            ]);
            $raw = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $error = curl_error($ch);

            if ($raw !== false && $status === 200) {
                return true;
            }

            $body = $raw === false ? '' : trim(substr((string) $raw, $headerSize));
            $this->logger->warning(sprintf(
                'Slack への送信に失敗しました (試行 %d/%d, HTTP %d) %s',
                $attempt, self::MAX_ATTEMPTS, $status, $error !== '' ? $error : $body,
            ));

            // Only rate limits and server errors are worth retrying.
            if ($raw !== false && $status !== 429 && $status < 500) {
                break;
            }
            if ($attempt < self::MAX_ATTEMPTS) {
                $wait = 2 ** $attempt;
                if ($status === 429 && preg_match('/^retry-after:\s*(\d+)/mi', (string) $raw, $m)) {
                    $wait = min((int) $m[1], 60);
                }
                sleep($wait);
            }
        }
        return false;
    }
}
