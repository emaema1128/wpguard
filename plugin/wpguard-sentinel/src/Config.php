<?php

namespace WPGuard\Sentinel;

/**
 * Settings come from constants in wp-config.php, not from the database,
 * so they cannot be changed from the admin screen or by SQL injection.
 */
final class Config
{
    /** @var string */
    public $webhook = '';
    /** @var string */
    public $siteName = '';
    /** @var string */
    public $mention = '<!channel>';
    /** @var bool */
    public $notifyInfo = false;
    /** @var string */
    public $timezone = 'Asia/Tokyo';
    /** @var int */
    public $loginMaxRetries = 5;
    /** @var int seconds in which failures are counted */
    public $loginWindow = 900;
    /** @var int seconds an IP stays locked */
    public $loginLockout = 900;
    /** @var string[] */
    public $trustedProxies = [];
    /** @var bool */
    public $allowXmlrpc = false;
    /** @var bool */
    public $allowFileEdit = false;

    public static function fromConstants(): self
    {
        $c = new self();
        $c->webhook = (string) self::constant('WPGUARD_SLACK_WEBHOOK', '');
        $c->siteName = (string) self::constant('WPGUARD_SITE_NAME', '');
        $c->mention = (string) self::constant('WPGUARD_SLACK_MENTION', '<!channel>');
        $c->notifyInfo = (bool) self::constant('WPGUARD_NOTIFY_INFO', false);
        $c->timezone = (string) self::constant('WPGUARD_TIMEZONE', 'Asia/Tokyo');
        $c->loginMaxRetries = max(1, (int) self::constant('WPGUARD_LOGIN_MAX_RETRIES', 5));
        $c->loginWindow = max(60, (int) self::constant('WPGUARD_LOGIN_WINDOW', 900));
        $c->loginLockout = max(60, (int) self::constant('WPGUARD_LOGIN_LOCKOUT', 900));
        $proxies = self::constant('WPGUARD_TRUSTED_PROXIES', []);
        $c->trustedProxies = is_array($proxies) ? array_map('strval', $proxies) : array_filter(array_map('trim', explode(',', (string) $proxies)));
        $c->allowXmlrpc = (bool) self::constant('WPGUARD_ALLOW_XMLRPC', false);
        $c->allowFileEdit = (bool) self::constant('WPGUARD_ALLOW_FILE_EDIT', false);
        return $c;
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    private static function constant(string $name, $default)
    {
        return defined($name) ? constant($name) : $default;
    }
}
