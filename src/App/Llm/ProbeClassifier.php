<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

/**
 * Lexical plausibility gate (Gate B of the LLM-fake decision, see docs/LLM-HONEYPOT-RESEARCH.md).
 *
 * Decides whether an otherwise-404 path *looks like* a real application path worth an LLM-generated
 * fake, or a random 404-fingerprinting / calibration probe that must get the plain, byte-identical
 * 404. It is deliberately default-deny: anything not positively plausible is treated as a probe, so
 * the honeypot never answers the random URLs dirbusters fire to baseline "nothing here".
 *
 * This gate cannot see per-IP behaviour (that is Gate A / the velocity tracker); it only judges the
 * string. It runs before the model is ever called and needs no network, so it is a pure, fast,
 * fully-testable classifier.
 */
final class ProbeClassifier
{
    /** Paths funnypot deliberately advertises (robots.txt bait): always worth a rich fake. */
    private const HARD_ALLOW = [
        '.git', '.env', 'wp-admin', 'wp-login', 'phpmyadmin', 'xmlrpc.php', 'phpinfo',
        'credentials.txt', 'backup.sql', '.aws', '.ssh', 'server-status', 'actuator',
    ];

    /** Identity / prompt-extraction probes. A real server just 404s these; letting the tuned model
     *  answer risks it echoing a loaded word from its own framing (see funnypot-llm GALAH-RESULTS).
     *  Matched against the path with all non-alphanumerics stripped, so separator/case variants
     *  collapse. Every entry is a multi-word compound that never occurs in a genuine app path. */
    private const IDENTITY_PROBE_TOKENS = [
        // authenticity / "what are you"
        'honeypot', 'honeytrap', 'areyoua', 'areyouan', 'areyoureal', 'areyoufake',
        'areyoubot', 'areyourobot', 'whoareyou', 'whatareyou', 'isthisa', 'isthisreal',
        'isthisfake', 'fakeserver', 'fakewebserver', 'decoy',
        // prompt extraction / injection
        'ignoreprevious', 'ignoreall', 'ignoreabove', 'ignoreyourinstruction',
        'printyourinstruction', 'printyourprompt', 'revealyourprompt', 'revealyourinstruction',
        'showyourprompt', 'showyourinstruction', 'systemprompt', 'jailbreak', 'promptinjection',
        'languagemodel', 'largelanguagemodel',
        // ChatML turn delimiters (<|im_start|> / <|im_end|>) collapsed: a path carrying one is trying
        // to author a prompt turn. Shed here so the HARD_ALLOW shortcut below can never route it on.
        'imstart', 'imend',
    ];

    /** Explicit calibration tells in a filename stem: an obvious "prove the 404" probe. */
    private const PROBE_TOKENS = [
        'random', 'nonexist', 'notfound', 'intentional', 'donotexist', 'shouldnotexist',
        'doesnotexist', 'thisdoesnotexist', 'test404', '404test', 'noexist', 'fakepath',
        // keyboard-walk calibration tokens scanners fire to baseline the 404
        'asdf', 'qwer', 'zxcv', 'qwerty', 'qazwsx', 'asdfgh', 'zxcvbn',
    ];

    /** Extensions a real web/app path plausibly ends in. An extension outside this set = probe. */
    private const EXT_ALLOW = [
        'php', 'php3', 'php4', 'php5', 'phtml', 'asp', 'aspx', 'ashx', 'asmx', 'jsp', 'jspx',
        'do', 'action', 'cgi', 'pl', 'py', 'rb', 'cfm', 'html', 'htm', 'shtml', 'xhtml',
        'json', 'xml', 'yml', 'yaml', 'conf', 'config', 'ini', 'env', 'properties',
        'bak', 'old', 'orig', 'save', 'swp', 'sql', 'db', 'zip', 'tar', 'gz', 'tgz', 'rar',
        'pem', 'key', 'crt', 'log', 'txt', 'md', 'js', 'css', 'map', 'git',
    ];

    /** Words that read as real app / directory names; a path containing one leans plausible. */
    private const APP_WORDS = [
        'admin', 'administrator', 'login', 'logout', 'signin', 'signup', 'register', 'auth',
        'oauth', 'sso', 'saml', 'token', 'session', 'password', 'passwd', 'reset', 'forgot',
        'user', 'users', 'account', 'accounts', 'profile', 'member', 'api', 'rest', 'graphql',
        'rpc', 'soap', 'config', 'settings', 'setup', 'install', 'dashboard', 'portal', 'panel',
        'console', 'manager', 'management', 'cms', 'wordpress', 'joomla', 'drupal', 'magento',
        'adminer', 'phpmyadmin', 'actuator', 'swagger', 'openapi', 'backup', 'backups', 'dump',
        'database', 'upload', 'uploads', 'file', 'files', 'download', 'downloads', 'media',
        'assets', 'static', 'public', 'private', 'internal', 'secure', 'vendor', 'includes',
        'content', 'server', 'status', 'health', 'healthz', 'metrics', 'info', 'debug', 'trace',
        'test', 'dev', 'staging', 'prod', 'app', 'application', 'web', 'service', 'services',
        'gateway', 'proxy', 'auth', 'billing', 'payment', 'checkout', 'cart', 'order', 'invoice',
        'report', 'reports', 'export', 'import', 'search', 'query', 'index', 'home', 'main',
        'default', 'error', 'maintenance', 'store', 'shop', 'blog', 'news', 'wp', 'cgi',
    ];

    /** @return 'plausible'|'probe' */
    public function classify(string $method, string $path): string
    {
        $path = $this->normalize($path);
        $lower = strtolower($path);

        // Identity/injection probes are shed to the plain 404 before any allow-list shortcut, so a
        // bait prefix (/wp-admin/are-you-a-honeypot) can't smuggle one through to the model.
        $collapsed = preg_replace('/[^a-z0-9]/', '', $lower) ?? $lower;
        foreach (self::IDENTITY_PROBE_TOKENS as $tok) {
            if (strpos($collapsed, $tok) !== false) {
                return 'probe';
            }
        }

        // Advertised bait always deserves a rich response.
        foreach (self::HARD_ALLOW as $bait) {
            if (strpos($lower, $bait) !== false) {
                return 'plausible';
            }
        }

        $segments = $this->segments($path);
        if ($segments === []) {
            return 'plausible';                   // "/" — never reaches here in practice
        }
        $leaf = (string) end($segments);
        $ext = strtolower($this->ext($leaf));

        // --- probe signals, checked over EVERY segment (a random directory is as damning as a
        // random leaf, so /aG7xK9pQ2/login.php must not pass on the plausible leaf alone) ---

        foreach ($segments as $seg) {
            $segStem = $this->stem($seg);
            $low = strtolower($segStem);
            $stripped = preg_replace('/[^a-z0-9]/', '', $low) ?? $low;   // 'should_not_exist' -> 'shouldnotexist'
            foreach (self::PROBE_TOKENS as $tok) {
                if (strpos($low, $tok) !== false || strpos($stripped, $tok) !== false) {
                    return 'probe';
                }
            }
            if (preg_match('/(^|[_.\-])404([_.\-]|$)/', $low) === 1) {
                return 'probe';
            }
            if ($this->looksRandom($segStem)) {
                return 'probe';                   // hex / uuid / numeric / mixed base62 / high-entropy
            }
        }
        // A dotfile config (.my.cnf, .npmrc, .bash_profile) is a classic scanner target. Allow it
        // before the extension gate, since its trailing "extension" (cnf, profile) is not a web one.
        if (preg_match('/^\.[a-z][a-z0-9._-]{1,40}$/', strtolower($leaf)) === 1) {
            return 'plausible';
        }
        if ($ext !== '' && !in_array($ext, self::EXT_ALLOW, true)) {
            return 'probe';                       // e.g. /foo.random, /x.qqq
        }

        // --- positive plausibility: a real signal is required. A recognised extension ALONE is NOT
        // enough (that was the /6qaz2wsx.php hole) — the path needs an app word or a pronounceable name. ---

        foreach ($segments as $seg) {
            $tokens = preg_split('/[^a-z0-9]+/', strtolower($this->stem($seg))) ?: [];
            foreach ($tokens as $tok) {
                if ($tok === '') {
                    continue;
                }
                foreach (self::APP_WORDS as $word) {
                    // short words need an exact token match (so 'wp' does not match inside gibberish);
                    // longer words may appear inside a concatenated token (adminlogin, userprofile).
                    if ($tok === $word || (strlen($word) >= 4 && strpos($tok, $word) !== false)) {
                        return 'plausible';
                    }
                }
            }
        }
        if ($this->pronounceable(strtolower($this->stem($leaf)))) {
            return 'plausible';                   // a product-name-shaped leaf, e.g. /kibana, /grafana, /login.asp
        }

        return 'probe';                           // default-deny
    }

    // --- helpers ---

    private function normalize(string $path): string
    {
        $path = '/' . ltrim($path, '/');
        $q = strpos($path, '?');
        if ($q !== false) {
            $path = substr($path, 0, $q);
        }

        return $path;
    }

    /** @return string[] non-empty path segments */
    private function segments(string $path): array
    {
        return array_values(array_filter(explode('/', $path), static fn (string $s): bool => $s !== ''));
    }

    /** The last non-empty segment (the "leaf"). */
    private function leaf(string $path): string
    {
        $segs = $this->segments($path);

        return $segs === [] ? '' : end($segs);
    }

    /** Filename without its extension. */
    private function stem(string $seg): string
    {
        $dot = strrpos($seg, '.');

        return $dot === false || $dot === 0 ? $seg : substr($seg, 0, $dot);
    }

    /** Extension after the last dot, or '' (a leading-dot dotfile has no extension). */
    private function ext(string $seg): string
    {
        $dot = strrpos($seg, '.');

        return $dot === false || $dot === 0 ? '' : substr($seg, $dot + 1);
    }

    /** Hex blob, UUID, long numeric, high-entropy, or a base62-shaped random token = random-looking. */
    private function looksRandom(string $stem): bool
    {
        if ($stem === '') {
            return false;
        }
        $low = strtolower($stem);
        if (preg_match('/^[a-f0-9]{8,}$/', $low) === 1) {
            return true;                          // hex digest
        }
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $low) === 1) {
            return true;                          // uuid
        }
        if (preg_match('/^\d{6,}$/', $stem) === 1) {
            return true;                          // long numeric id-as-path
        }
        if (strlen($low) >= 10 && $this->entropy($low) >= 3.7) {
            return true;                          // long high-entropy token
        }

        // Base62-shaped calibration token (6qaz2wsx, aG7xK9pQ2): long enough, carries a digit, is not
        // a pronounceable word, and either mixes case or interleaves digits (not a trailing id like
        // login2 / user123, which stay pronounceable).
        if (strlen($stem) >= 8 && preg_match('/\d/', $stem) === 1 && !$this->pronounceable($low)) {
            $mixedCase = preg_match('/[a-z]/', $stem) === 1 && preg_match('/[A-Z]/', $stem) === 1;
            $digitInterleaved = preg_match('/\d[a-z]/i', $stem) === 1;   // a digit immediately before a letter
            if ($mixedCase || $digitInterleaved) {
                return true;
            }
        }

        return false;
    }

    private function entropy(string $s): float
    {
        $len = strlen($s);
        if ($len === 0) {
            return 0.0;
        }
        $freq = count_chars($s, 1);
        $h = 0.0;
        foreach ($freq as $count) {
            $p = $count / $len;
            $h -= $p * log($p, 2);
        }

        return $h;
    }

    /** A pronounceable, product-name-shaped token: real vowel ratio, no long consonant runs. */
    private function pronounceable(string $stem): bool
    {
        $stem = preg_replace('/[^a-z]/', '', $stem) ?? '';
        $len = strlen($stem);
        if ($len < 3 || $len > 24) {
            return false;
        }
        $vowels = preg_match_all('/[aeiou]/', $stem);
        $ratio = $vowels / $len;
        if ($ratio < 0.20 || $ratio > 0.75) {
            return false;                         // too few / too many vowels reads as random
        }

        return preg_match('/[bcdfghjklmnpqrstvwxyz]{5,}/', $stem) !== 1;   // no 5+ consonant run
    }
}
