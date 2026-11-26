<?php

namespace WPGuard\Sentinel;

/**
 * Time-based one-time passwords (RFC 6238): 6 digits, 30-second steps, HMAC-SHA1.
 * Works with Google Authenticator, Microsoft Authenticator, 1Password, Authy, ...
 */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const STEP = 30;
    private const DIGITS = 6;
    /** Accept the previous and next code too, for phones whose clock is slightly off. */
    private const WINDOW = 1;

    public static function newSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    public static function code(string $secret, int $step): string
    {
        $key = self::base32Decode($secret);
        $hash = hash_hmac('sha1', pack('N*', 0, $step), $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);
        return str_pad((string) ($value % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Returns the time step the code belongs to, or null when it is wrong.
     * Steps at or before $lastStep are refused, so an intercepted code cannot be replayed.
     */
    public static function verify(string $secret, string $code, int $lastStep, ?int $now = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code);
        if (!is_string($code) || !preg_match('/^\d{6}$/', $code)) {
            return null;
        }
        $current = intdiv($now ?? time(), self::STEP);
        for ($i = -self::WINDOW; $i <= self::WINDOW; $i++) {
            $step = $current + $i;
            if ($step > $lastStep && hash_equals(self::code($secret, $step), $code)) {
                return $step;
            }
        }
        return null;
    }

    /** otpauth:// link; tapping it on a phone adds the account to the authenticator app. */
    public static function uri(string $secret, string $account, string $issuer): string
    {
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
            rawurlencode($issuer), rawurlencode($account), $secret, rawurlencode($issuer), self::DIGITS, self::STEP
        );
    }

    /** "ABCD EFGH IJKL ..." for typing into an app by hand. */
    public static function grouped(string $secret): string
    {
        return trim(chunk_split($secret, 4, ' '));
    }

    public static function base32Encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    public static function base32Decode(string $s): string
    {
        $s = strtoupper(preg_replace('/[\s=]/', '', $s) ?? '');
        $bits = '';
        foreach (str_split($s) as $c) {
            $i = strpos(self::ALPHABET, $c);
            if ($i === false) {
                return '';
            }
            $bits .= str_pad(decbin($i), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }
}
