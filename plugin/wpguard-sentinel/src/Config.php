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
    /** @var bool */
    public $twoFactor = true;
    /** @var string[] roles that must use two-factor authentication */
    public $twoFactorRoles = ['administrator'];
    /** @var int */
    public $twoFactorGraceDays = 7;
    /** @var bool */
    public $twoFactorAllowAppPasswords = false;
    /** @var bool */
    public $securityHeaders = true;
    /** @var string SAMEORIGIN, DENY or '' (none) */
    public $frameOptions = 'SAMEORIGIN';
    /** @var string */
    public $permissionsPolicy = 'camera=(), microphone=(), usb=()';
    /** @var int HSTS max-age in seconds, 0 = off */
    public $hsts = 0;
    /** @var bool */
    public $auditLog = true;
    /** @var bool */
    public $auditSyslog = true;
    /** @var string extra copy of the audit log, one line per entry ('' = none) */
    public $auditFile = '';
    /** @var int */
    public $auditDays = 90;

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
        $c->twoFactor = (bool) self::constant('WPGUARD_2FA', true);
        $roles = self::constant('WPGUARD_2FA_ROLES', ['administrator']);
        $c->twoFactorRoles = is_array($roles) ? array_map('strval', $roles) : array_filter(array_map('trim', explode(',', (string) $roles)));
        $c->twoFactorGraceDays = max(0, (int) self::constant('WPGUARD_2FA_GRACE_DAYS', 7));
        $c->twoFactorAllowAppPasswords = (bool) self::constant('WPGUARD_2FA_ALLOW_APP_PASSWORDS', false);
        $c->securityHeaders = (bool) self::constant('WPGUARD_SECURITY_HEADERS', true);
        $frame = strtoupper((string) self::constant('WPGUARD_FRAME_OPTIONS', 'SAMEORIGIN'));
        $c->frameOptions = in_array($frame, ['SAMEORIGIN', 'DENY'], true) ? $frame : '';
        $c->permissionsPolicy = trim((string) self::constant('WPGUARD_PERMISSIONS_POLICY', 'camera=(), microphone=(), usb=()'));
        $c->hsts = max(0, (int) self::constant('WPGUARD_HSTS', 0));
        $c->auditLog = (bool) self::constant('WPGUARD_AUDIT_LOG', true);
        $c->auditSyslog = (bool) self::constant('WPGUARD_AUDIT_SYSLOG', true);
        $c->auditFile = (string) self::constant('WPGUARD_AUDIT_FILE', '');
        $c->auditDays = max(1, (int) self::constant('WPGUARD_AUDIT_DAYS', 90));
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
