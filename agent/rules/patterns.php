<?php

/*
 * 怪しいコードの検出ルール
 *
 * targets:
 *   php       … PHP として実行されうるファイル (.php, .phtml, .phar など)
 *   htaccess  … .htaccess / .user.ini
 *   uploads   … uploads 内の PHP 以外のファイル (画像などに偽装した PHP を探す)
 *
 * 公式配布版と一致したファイル (WordPress 本体・公式リポジトリのプラグイン) はスキャンしません。
 * 誤検知が多いルールを見つけたら severity を下げるか、ルールごと削除してください。
 */

return [
    // ---------------------------------------------------------------- 緊急
    [
        'id' => 'eval-decode',
        'severity' => 'critical',
        'targets' => ['php', 'uploads'],
        'description' => 'eval と復号処理の組み合わせ (典型的なバックドア)',
        'regex' => '/\b(eval|assert)\s*\(\s*@?\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode|convert_uudecode)\s*\(/i',
    ],
    [
        'id' => 'exec-request',
        'severity' => 'critical',
        'targets' => ['php', 'uploads'],
        'description' => '外部からの入力をそのまま実行している (Web シェル)',
        'regex' => '/\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)\s*\(\s*@?\s*(stripslashes\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/i',
    ],
    [
        'id' => 'call-request',
        'severity' => 'critical',
        'targets' => ['php', 'uploads'],
        'description' => '外部からの入力を関数名として呼び出している (Web シェル)',
        'regex' => '/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/i',
    ],
    [
        'id' => 'preg-replace-e',
        'severity' => 'critical',
        'targets' => ['php', 'uploads'],
        'description' => 'preg_replace の /e 修飾子によるコード実行',
        'regex' => '/preg_replace\s*\(\s*([\'"])([^\w\s\\\\]).{0,200}?\2[imsxuADSUXJ]*e[imsxuADSUXJ]*\1\s*,/i',
    ],
    [
        'id' => 'webshell-name',
        'severity' => 'critical',
        'targets' => ['php', 'uploads'],
        'description' => '既知の Web シェルの特徴的な文字列',
        'regex' => '/(FilesMan|wso_version|b374k|c99shell|r57shell|IndoXploit|AlfaShell|\bAnonymousFox\b|uname\s*-a.{0,40}safe_mode)/i',
    ],
    [
        'id' => 'php-in-media',
        'severity' => 'critical',
        'targets' => ['uploads'],
        'description' => '画像などに偽装した PHP コード',
        'regex' => '/<\?(php\b|=)/i',
    ],
    [
        'id' => 'htaccess-prepend',
        'severity' => 'critical',
        'targets' => ['htaccess'],
        'description' => 'すべてのページに PHP を差し込む設定 (auto_prepend_file)',
        'regex' => '/\bauto_(prepend|append)_file\b/i',
    ],

    // ---------------------------------------------------------------- 警告
    [
        'id' => 'htaccess-php-handler',
        'severity' => 'warning',
        'targets' => ['htaccess'],
        'description' => 'PHP 以外の拡張子を PHP として実行させる設定',
        'regex' => '/^\s*(AddHandler|SetHandler|AddType)\b[^\n]*(php|x-httpd)/im',
    ],
    [
        'id' => 'htaccess-redirect',
        'severity' => 'warning',
        'targets' => ['htaccess'],
        'description' => '検索エンジンやスマホからのアクセスだけを外部に転送する設定',
        'regex' => '/RewriteCond\s+%\{HTTP_(REFERER|USER_AGENT)\}[^\n]*(google|bing|yahoo|android|iphone|mobile)[\s\S]{0,300}RewriteRule[^\n]*https?:\/\//i',
    ],
    [
        'id' => 'obfuscated-decode',
        'severity' => 'warning',
        'targets' => ['php'],
        'description' => '多重に難読化されたコード',
        'regex' => '/\b(gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*(base64_decode|str_rot13|gzinflate|strrev)\s*\(/i',
    ],
    [
        'id' => 'long-base64',
        'severity' => 'warning',
        'targets' => ['php'],
        'description' => '非常に長い base64 文字列 (隠されたコードの可能性)',
        'regex' => '/[\'"][A-Za-z0-9+\/]{3000,}={0,2}[\'"]/',
    ],
    [
        'id' => 'hex-escape',
        'severity' => 'warning',
        'targets' => ['php'],
        'description' => '16 進エスケープで隠された文字列',
        'regex' => '/(\\\\x[0-9a-f]{2}){40,}/i',
    ],
    [
        'id' => 'chr-chain',
        'severity' => 'warning',
        'targets' => ['php'],
        'description' => 'chr() を連結して作られた文字列',
        'regex' => '/(chr\s*\(\s*\d+\s*\)\s*\.\s*){12,}/i',
    ],
    [
        'id' => 'remote-include',
        'severity' => 'warning',
        'targets' => ['php'],
        'description' => '外部 URL のコードを読み込んでいる',
        'regex' => '/\b(include|require)(_once)?\s*\(?\s*[\'"](https?|ftp):\/\//i',
    ],
    [
        'id' => 'variable-function-decode',
        'severity' => 'warning',
        'targets' => ['php'],
        'description' => '文字列から組み立てた関数名を呼び出している',
        'regex' => '/\$\w+\s*=\s*[\'"](base64_decode|str_rot13|gzinflate|assert|eval)[\'"]\s*;.{0,200}\$\w+\s*\(/is',
    ],
];
