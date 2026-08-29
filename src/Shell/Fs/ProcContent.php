<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/**
 * Extension-aware body for a procedurally-generated file. A `cat` of a generated `.env`, `.conf`,
 * `.json` or `.log` should read as that kind of file, not the base64 noise every file used to emit —
 * generic noise inside a name like `config.json` is itself the tell. Content is a pure function of
 * (seed, name, size): deterministic, inert (no real secret, host, or key material), and ALWAYS
 * exactly $size bytes, because a file's `ls -l` size is drawn before content and the two must agree.
 *
 * Unknown / binary extensions fall through to the same avalanching base64 the old generator used, so
 * those files are byte-for-byte unchanged.
 */
final class ProcContent
{
    // '=' assignment separators / values must be believable but carry nothing real.
    private const KEYS = [
        'APP_ENV', 'APP_DEBUG', 'LOG_LEVEL', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD',
        'REDIS_HOST', 'REDIS_PORT', 'CACHE_DRIVER', 'QUEUE_CONNECTION', 'MAIL_HOST', 'MAIL_PORT',
        'SESSION_LIFETIME', 'MAX_UPLOAD', 'WORKERS', 'TIMEOUT', 'RETRY_LIMIT', 'POOL_SIZE',
        'ENABLE_METRICS', 'REGION', 'BUCKET', 'ENDPOINT', 'API_URL', 'SMTP_USER', 'THREADS', 'KEEPALIVE',
    ];
    private const WORDS = [
        'production', 'staging', 'primary', 'replica', 'worker', 'gateway', 'internal', 'edge', 'core',
        'default', 'enabled', 'disabled', 'redis', 'postgres', 'nginx', 'app', 'api', 'web', 'cache',
    ];
    private const LEVELS = ['INFO', 'WARN', 'ERROR', 'DEBUG', 'NOTICE'];
    private const UNITS = ['svc', 'worker', 'nginx', 'db', 'cron', 'auth', 'api', 'cache'];

    private const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    /** Bodies keyed by extension family. */
    public static function generate(string $seed, string $name, int $size): string
    {
        if ($size <= 0) {
            return '';
        }
        switch (self::kindOf($name)) {
            case 'keyval':
                return self::keyval($seed, $size, '=');
            case 'yaml':
                return self::keyval($seed, $size, ': ');
            case 'log':
                return self::log($seed, $size);
            case 'sql':
                return self::sql($seed, $size);
            case 'json':
                return self::json($seed, $size);
            case 'pem':
                return self::pem($seed, $size);
            default:
                return self::noise($seed, $size);
        }
    }

    private static function kindOf(string $name): string
    {
        $lower = strtolower($name);
        if ($lower === '.env' || strncmp($lower, '.env.', 5) === 0) {
            return 'keyval';
        }
        $dot = strrpos($lower, '.');
        $ext = $dot === false ? '' : substr($lower, $dot + 1);
        switch ($ext) {
            case 'env': case 'ini': case 'cfg': case 'conf': case 'toml': case 'hcl':
            case 'tf': case 'tfvars': case 'properties':
                return 'keyval';
            case 'yaml': case 'yml':
                return 'yaml';
            case 'log':
                return 'log';
            case 'sql':
                return 'sql';
            case 'json':
                return 'json';
            case 'pem': case 'key': case 'crt': case 'cer':
                return 'pem';
            default:
                return 'noise';
        }
    }

    /** KEY<sep>value lines, filled to EXACTLY $size with a trailing `#` comment (valid in every
     *  keyval/yaml format we route here). */
    private static function keyval(string $seed, int $size, string $sep): string
    {
        $buf = '';
        $i = 0;
        while (true) {
            $key = (string) Draw::pick($seed, 200 + $i * 3, self::KEYS);
            $line = $key . $sep . self::value($seed, 201 + $i * 3) . "\n";
            if (strlen($buf) + strlen($line) > $size) {
                break;
            }
            $buf .= $line;
            if (strlen($buf) === $size) {
                return $buf;
            }
            $i++;
        }

        return $buf . self::commentFill($seed, $size - strlen($buf));
    }

    private static function value(string $seed, int $i): string
    {
        $r = Draw::at($seed, $i) % 5;
        if ($r === 0) {
            return (string) (Draw::at($seed, $i + 100000) % 65535);           // a port / number
        }
        if ($r === 1) {
            return Draw::chance($seed, $i + 200000, 1, 2) ? 'true' : 'false';   // a flag
        }
        if ($r === 2) {
            return (string) Draw::pick($seed, $i + 300000, self::WORDS);        // a word
        }
        if ($r === 3) {
            return self::alnum($seed, 'v' . $i, 24 + (Draw::at($seed, $i + 400000) % 16)); // a token
        }

        return '10.0.' . (Draw::at($seed, $i + 500000) % 255) . '.' . (Draw::at($seed, $i + 600000) % 255); // an ip
    }

    private static function log(string $seed, int $size): string
    {
        $buf = '';
        $i = 0;
        while (true) {
            $line = self::logLine($seed, $i);
            if (strlen($buf) + strlen($line) > $size) {
                break;
            }
            $buf .= $line;
            if (strlen($buf) === $size) {
                return $buf;
            }
            $i++;
        }

        // A log's final line is legitimately partial (it is appended to continuously), so fill the
        // remainder with a truncated log line rather than a comment.
        $rem = $size - strlen($buf);
        if ($rem <= 0) {
            return $buf;
        }

        return $buf . substr(self::logLine($seed, $i), 0, $rem - 1) . "\n";
    }

    private static function logLine(string $seed, int $i): string
    {
        $h = Draw::at($seed, 700 + $i);
        $ts = sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ', 2026, 1 + $h % 8, 1 + ($h >> 3) % 27,
            ($h >> 8) % 24, ($h >> 13) % 60, ($h >> 19) % 60);
        $level = (string) Draw::pick($seed, 701 + $i * 2, self::LEVELS);
        $unit = (string) Draw::pick($seed, 702 + $i * 2, self::UNITS);
        $msg = (string) Draw::pick($seed, 703 + $i * 2, self::WORDS);

        return "{$ts} {$level} {$unit}[" . (100 + $h % 9000) . "]: {$msg} " . self::alnum($seed, 'lg' . $i, 8) . "\n";
    }

    private static function sql(string $seed, int $size): string
    {
        $buf = '';
        $i = 0;
        while (true) {
            $tbl = (string) Draw::pick($seed, 810 + $i, self::UNITS);
            $line = "INSERT INTO {$tbl} VALUES (" . (1 + Draw::at($seed, 811 + $i) % 99999)
                . ", '" . self::alnum($seed, 'sq' . $i, 12) . "');\n";
            if (strlen($buf) + strlen($line) > $size) {
                break;
            }
            $buf .= $line;
            if (strlen($buf) === $size) {
                return $buf;
            }
            $i++;
        }

        return $buf . self::sqlFill($seed, $size - strlen($buf));
    }

    /** A `-- ` comment line of exactly $rem bytes (SQL comment syntax). */
    private static function sqlFill(string $seed, int $rem): string
    {
        if ($rem <= 0) {
            return '';
        }
        if ($rem === 1) {
            return "\n";
        }
        if ($rem === 2) {
            return "-\n";
        }
        if ($rem === 3) {
            return "--\n";
        }

        return '-- ' . self::alnum($seed, 'sf', $rem - 4) . "\n"; // 3 + (rem-4) + 1
    }

    /** A `#` comment line of exactly $rem bytes. */
    private static function commentFill(string $seed, int $rem): string
    {
        if ($rem <= 0) {
            return '';
        }
        if ($rem === 1) {
            return "\n";
        }
        if ($rem === 2) {
            return "#\n";
        }

        return '# ' . self::alnum($seed, 'cf', $rem - 3) . "\n"; // 2 + (rem-3) + 1
    }

    /**
     * A single JSON object, EXACTLY $size bytes: complete `"key": "value",` lines, then a final
     * comma-free pair whose value absorbs the remaining bytes. Tiny sizes fall back to noise (a
     * 5-byte "config.json" is not worth faking, and can't hold a wrapped object).
     */
    private static function json(string $seed, int $size): string
    {
        if ($size < 16) {
            return self::noise($seed, $size);
        }
        $open = "{\n";
        $close = "\n}";
        $inner = $size - strlen($open) - strlen($close);   // >= 12
        // The final, comma-free pair is fixed up front so the loop can reserve its exact length; its
        // value then absorbs whatever bytes are left, landing the object on $size to the byte.
        $prefix = '  "' . strtolower((string) Draw::pick($seed, 950, self::KEYS)) . '": "';
        $suffix = '"';
        $reserve = strlen($prefix) + strlen($suffix);
        if ($inner < $reserve) {
            return self::noise($seed, $size);              // too small to hold a wrapped object
        }
        $lines = '';
        $i = 0;
        while (true) {
            $pair = '  "' . strtolower((string) Draw::pick($seed, 900 + $i * 2, self::KEYS)) . '": "'
                . self::value($seed, 901 + $i * 2) . '",' . "\n";
            if (strlen($lines) + strlen($pair) + $reserve > $inner) {
                break;
            }
            $lines .= $pair;
            $i++;
        }
        $padLen = $inner - strlen($lines) - $reserve;
        $final = $prefix . self::alnum($seed, 'jf', $padLen) . $suffix;

        return $open . $lines . $final . $close;
    }

    /** An inert PEM block sized exactly to $size — BEGIN/END lines with a wrapped base64 body. */
    private static function pem(string $seed, int $size): string
    {
        $head = "-----BEGIN PRIVATE KEY-----\n";
        $tail = "-----END PRIVATE KEY-----\n";
        if ($size < strlen($head) + strlen($tail) + 1) {
            return self::noise($seed, $size);
        }
        $bodyLen = $size - strlen($head) - strlen($tail);   // newlines between 64-col lines count here
        $chars = self::alnum($seed, 'pem', $bodyLen);       // more than enough base64 chars
        $body = '';
        $col = 0;
        $c = 0;
        while (strlen($body) < $bodyLen) {
            // A newline every 64 columns; each newline is one of the $bodyLen bytes, so the block ends
            // exactly on $size wherever the wrap falls.
            if ($col === 64) {
                $body .= "\n";
                $col = 0;
                continue;
            }
            $body .= $chars[$c++];
            $col++;
        }

        return $head . $body . $tail;
    }

    /**
     * Avalanching, padding-free base64 — the original generator, kept byte-identical for fall-through
     * so unknown/binary files are unchanged. The 5000000 block-counter base is a fixed draw namespace
     * (stays < 2^32) that must not shift, or every non-config file's bytes would move.
     */
    private static function noise(string $seed, int $size): string
    {
        $rawNeeded = intdiv($size, 4) * 3 + 3;
        $raw = '';
        $b = 0;
        while (strlen($raw) < $rawNeeded) {
            $raw .= md5($seed . pack('N', 5000000 + $b), true);
            $b++;
        }

        return substr(base64_encode($raw), 0, $size);
    }

    /** Exactly $n chars from a byte-avalanching alphabet stream (never '='), keyed by (seed, tag). */
    private static function alnum(string $seed, string $tag, int $n): string
    {
        if ($n <= 0) {
            return '';
        }
        $out = '';
        $block = 0;
        $m = strlen(self::B64URL);
        while (strlen($out) < $n) {
            $bytes = md5($seed . "\0" . $tag . "\0" . $block, true);
            for ($k = 0; $k < 16 && strlen($out) < $n; $k++) {
                $out .= self::B64URL[ord($bytes[$k]) % $m];
            }
            $block++;
        }

        return $out;
    }
}
