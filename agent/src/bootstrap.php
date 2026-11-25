<?php

declare(strict_types=1);

if (PHP_VERSION_ID < 80100) {
    fwrite(STDERR, "WPGuard には PHP 8.1 以上が必要です (現在: " . PHP_VERSION . ")\n");
    exit(2);
}

foreach (['pdo_sqlite', 'hash'] as $ext) {
    if (!extension_loaded($ext)) {
        fwrite(STDERR, "PHP 拡張モジュール {$ext} が必要です\n");
        exit(2);
    }
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'WPGuard\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

// Turn unexpected warnings into exceptions. Calls prefixed with @ are left alone.
set_error_handler(static function (int $errno, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $errno)) {
        return false;
    }
    throw new ErrorException($message, 0, $errno, $file, $line);
});
