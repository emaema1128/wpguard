<?php

declare(strict_types=1);

namespace WPGuard;

final class Logger
{
    /** @var resource|null */
    private $handle = null;

    public function __construct(?string $file, private bool $verbose = false)
    {
        if ($file === null || $file === '') {
            return;
        }
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $h = @fopen($file, 'ab');
        if ($h === false) {
            fwrite(STDERR, "[wpguard] ログファイルを開けません: {$file} (標準エラー出力のみに記録します)\n");
            $this->verbose = true;
            return;
        }
        $this->handle = $h;
    }

    public function info(string $msg): void
    {
        $this->write('INFO', $msg);
    }

    public function warning(string $msg): void
    {
        $this->write('WARN', $msg);
    }

    public function error(string $msg): void
    {
        $this->write('ERROR', $msg);
    }

    private function write(string $level, string $msg): void
    {
        $line = sprintf("%s [%s] %s\n", date('Y-m-d H:i:s'), $level, $msg);
        if ($this->handle !== null) {
            fwrite($this->handle, $line);
        }
        if ($this->verbose || $level === 'ERROR') {
            fwrite(STDERR, $line);
        }
    }
}
