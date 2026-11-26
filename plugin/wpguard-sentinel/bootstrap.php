<?php

if (!defined('ABSPATH')) {
    exit;
}

define('WPGUARD_SENTINEL_VERSION', '0.1.0');

require_once __DIR__ . '/src/Config.php';
require_once __DIR__ . '/src/ClientIp.php';
require_once __DIR__ . '/src/Notifier.php';
require_once __DIR__ . '/src/LoginGuard.php';
require_once __DIR__ . '/src/UserMonitor.php';
require_once __DIR__ . '/src/ChangeMonitor.php';
require_once __DIR__ . '/src/Hardening.php';
require_once __DIR__ . '/src/CronMonitor.php';
require_once __DIR__ . '/src/Totp.php';
require_once __DIR__ . '/src/TwoFactor.php';

// Server-wide settings shared by every site (root-owned, readable by the web server).
// Constants already defined in wp-config.php take precedence.
$wpguard_shared = defined('WPGUARD_SHARED_CONFIG') ? (string) WPGUARD_SHARED_CONFIG : '/etc/wpguard/sentinel.php';
if ($wpguard_shared !== '' && @is_readable($wpguard_shared)) {
    include_once $wpguard_shared;
}
unset($wpguard_shared);

// Nothing to protect while WordPress itself is being installed.
if (!(defined('WP_INSTALLING') && WP_INSTALLING)) {
    $wpguard_config = WPGuard\Sentinel\Config::fromConstants();
    WPGuard\Sentinel\Notifier::init($wpguard_config);
    WPGuard\Sentinel\Hardening::register($wpguard_config);
    WPGuard\Sentinel\LoginGuard::register($wpguard_config);
    WPGuard\Sentinel\UserMonitor::register();
    WPGuard\Sentinel\ChangeMonitor::register();
    WPGuard\Sentinel\CronMonitor::register();
    WPGuard\Sentinel\TwoFactor::register($wpguard_config);
    unset($wpguard_config);
}
