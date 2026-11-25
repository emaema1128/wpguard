<?php
/**
 * Plugin Name: WPGuard Sentinel
 * Description: ログイン保護・管理者の監視・サイトの防御設定を行い、Slack に通知します。(mu-plugin)
 * Version: 0.1.0
 * Requires PHP: 7.4
 *
 * WordPress は mu-plugins のサブディレクトリを読み込まないため、このファイルが本体を読み込みます。
 * 配置: wp-content/mu-plugins/wpguard-sentinel.php と wp-content/mu-plugins/wpguard-sentinel/
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/wpguard-sentinel/bootstrap.php';
