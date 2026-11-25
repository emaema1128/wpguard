<?php

declare(strict_types=1);

namespace WPGuard;

final class Config
{
    private const DEFAULTS = [
        'roots' => ['/var/www'],
        'discovery_max_depth' => 4,
        'site_names' => [],
        'data_dir' => '/var/lib/wpguard',
        'log_file' => '/var/log/wpguard/wpguard.log',
        'timezone' => 'Asia/Tokyo',
        'exclude' => ['wp-content/cache/*'],
        'max_hash_bytes' => 100 * 1024 * 1024,
        'notify_min_severity' => 'warning',
        'dedupe_hours' => 6,
        'aggregate_threshold' => 10,
        'slack' => [
            'webhook_url' => '',
            'webhooks' => [],
            'mention_critical' => '<!channel>',
            'timeout' => 10,
        ],
    ];

    private function __construct(private array $data, public readonly string $path)
    {
    }

    public static function load(?string $path = null): self
    {
        $path ??= (getenv('WPGUARD_CONFIG') ?: dirname(__DIR__) . '/config.php');
        if (!is_file($path)) {
            throw new \RuntimeException(
                "設定ファイルが見つかりません: {$path}\n"
                . "config.example.php をコピーして config.php を作成してください。"
            );
        }
        $user = require $path;
        if (!is_array($user)) {
            throw new \RuntimeException("設定ファイルは配列を return する必要があります: {$path}");
        }
        return self::fromArray($user, $path);
    }

    public static function fromArray(array $user, string $path = '(inline)'): self
    {
        $data = array_replace(self::DEFAULTS, $user);
        $data['slack'] = array_replace(self::DEFAULTS['slack'], $user['slack'] ?? []);

        if (!is_array($data['roots']) || $data['roots'] === []) {
            throw new \RuntimeException('roots には監視するディレクトリを1つ以上指定してください');
        }
        if (Severity::tryFrom((string) $data['notify_min_severity']) === null) {
            throw new \RuntimeException('notify_min_severity は critical / warning / info のいずれかです');
        }
        foreach (array_keys($data['slack']['webhooks']) as $sev) {
            if (Severity::tryFrom((string) $sev) === null) {
                throw new \RuntimeException("slack.webhooks のキーが不正です: {$sev}");
            }
        }

        return new self($data, $path);
    }

    public function get(string $key): mixed
    {
        return $this->data[$key] ?? null;
    }

    public function slack(string $key): mixed
    {
        return $this->data['slack'][$key] ?? null;
    }
}
