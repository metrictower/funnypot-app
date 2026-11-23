<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Bench\SsrfPivotCrawler;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/scripts/support/SsrfPivotCrawler.php';
require_once dirname(__DIR__, 4) . '/demo/lib/geo.php';

/**
 * The SSRF decoy never makes an outbound request or a DNS lookup. There is no fetch code, and four
 * checks with stated reach keep it that way:
 *
 * (1) a static allowlist over the SSRF namespaces and the build stamp: only listed pure built-ins (and
 *     the build stamp's own local-file reads), own or listed classes, listed static calls, no parent
 *     class outside the namespace, no anonymous class, no dynamic call of any shape, no include, eval,
 *     output, superglobal, clock or randomness; one positive-control fixture per rule;
 * (2) the bench in a child PHP started with -n that disables every function of every loaded extension
 *     outside PURE_EXTENSIONS plus the network-capable functions of those (the child checks each name is
 *     gone and that no other extension loaded), URL wrappers off and a dead sendmail; it cannot see quiet
 *     stat calls on URLs, and the planted control documents that blind spot;
 * (3) recording stream wrappers around the same journey in this process, which see every URL operation;
 * (4) the edited-file pin: every file outside the namespaces that this work edits or adds may gain no
 *     call, class, static call or parent beyond its base set and the listed DELTA.
 */
final class SsrfNoOutboundTest extends TestCase
{
    private const BASE_FIXTURE = 'tests/Fixtures/ssrf/edited-files-base.json';
    private const STEPS = 300;

    /** Names an edited file may gain, per kind. Only the SSRF decoy's own classes and pure helpers. */
    private const DELTA = [
        'calls' => ['max', 'preg_replace'],
        'new' => ['Funnypot\\App\\Storage\\SsrfStore'],
        'static' => [
            'self::gatewaylines',
            'Funnypot\\App\\Tarpit\\Mint\\SurfaceExtension::none',
            'Funnypot\\App\\Tarpit\\Ssrf\\SsrfDecoy::build',
            'Funnypot\\App\\Tarpit\\Ssrf\\SsrfRoutes::extension',
            // the build stamp the key index versions on: the image's build id or a hash of local sources, plus
            // the installed core reference read from composer's own map
            'Funnypot\\App\\Config\\BuildStamp::value',
            'Composer\\InstalledVersions::getreference',
        ],
        'extends' => [],
    ];

    /** Pure built-ins the namespace may call. Every one transforms its arguments and touches nothing else. */
    public const FUNCTIONS = [
        'array_diff_key', 'array_fill_keys', 'array_filter', 'array_intersect', 'array_is_list', 'array_key_exists', 'array_keys', 'array_map',
        'array_merge', 'array_reverse', 'array_shift', 'array_slice', 'array_splice', 'array_unique', 'array_values', 'basename', 'ceil', 'count',
        'crc32', 'ctype_digit', 'ctype_xdigit', 'error_log', 'explode', 'filter_var', 'get_class', 'gettype', 'gmdate', 'hash', 'hash_equals',
        'hash_final', 'hash_hmac', 'hash_init', 'hash_update', 'hex2bin', 'hexdec', 'htmlspecialchars', 'implode', 'in_array', 'inet_ntop',
        'inet_pton', 'intdiv', 'intval', 'is_array', 'is_int', 'is_string', 'json_decode', 'json_encode', 'ltrim', 'max', 'min', 'octdec', 'ord',
        'preg_match', 'preg_match_all', 'preg_quote', 'preg_replace', 'rawurldecode', 'rawurlencode', 'rtrim', 'sprintf', 'str_contains',
        'str_ends_with', 'str_repeat', 'str_replace', 'str_split', 'str_starts_with', 'strcspn', 'stripos', 'strlen', 'strncmp', 'strpbrk',
        'strpos', 'strrpos', 'strspn', 'strtolower', 'strtr', 'substr', 'trim', 'ucfirst', 'unpack',
    ];

    /** Classes outside the namespaces the namespace may instantiate. */
    public const CLASSES = [
        'LogicException', 'RuntimeException', 'InvalidArgumentException', 'DomainException', 'UnexpectedValueException',
        'Funnypot\\App\\Tarpit\\ConfigDump', 'Funnypot\\App\\Tarpit\\HostileFormat', 'Funnypot\\App\\Tarpit\\LogRabbitHole',
        'Funnypot\\Shell\\Fs\\FakeFilesystem', 'Funnypot\\Core\\Template\\DirectiveRenderer', 'Funnypot\\Core\\RequestContext',
        'Funnypot\\App\\Tarpit\\Mint\\DecoyPrincipalResolver', 'Funnypot\\App\\Tarpit\\Mint\\SurfaceExtension',
    ];

    /** Static calls outside the namespaces the namespace may make. */
    public const STATIC = [
        'Funnypot\\App\\Render\\Fake\\Fleet::fromSeed', 'Funnypot\\App\\Tarpit\\InertSecret::isClean', 'Funnypot\\App\\Render\\Fake\\FakeSecrets::fromSeed',
        'Funnypot\\Shell\\Fs\\Draw::seed', 'Funnypot\\Core\\Support\\PersonaIdentity::fromSeed', 'Funnypot\\App\\Tarpit\\Mint\\MintContext::out',
        'Funnypot\\App\\Tarpit\\Mint\\MintPlan::empty', 'Funnypot\\App\\Tarpit\\Mint\\MintPlan::html', 'Funnypot\\App\\Tarpit\\Mint\\MintPlan::json',
        'Funnypot\\App\\Tarpit\\Mint\\MintPlan::redirect', 'Funnypot\\App\\Tarpit\\Mint\\MintRequest::parse', 'Funnypot\\App\\Tarpit\\Mint\\TokenMintDecoy::nonDisclosing',
        'Funnypot\\App\\Tarpit\\Mint\\AccountPages::e', 'Funnypot\\App\\Http\\HoneypotController::decoyForPath', 'Funnypot\\App\\Tarpit\\Mint\\MintRoutes::coreKeyed',
        'Funnypot\\App\\Tarpit\\Mint\\MintRoutes::normalise', 'Funnypot\\App\\Storage\\Sqlite::open', 'Funnypot\\App\\Tarpit\\Mint\\MintVocabulary::text',
    ];

    /** The one network-capable class client the namespace may reach, and only from the stores. */
    private const STORE_ONLY = ['Funnypot\\App\\Storage\\Sqlite::open' => ['SsrfStore.php', 'SsrfKeyIndex.php']];

    /** The build stamp reads fixed files under the app root; no other scanned file may read a file. */
    private const FILE_ONLY = ['BuildStamp.php' => ['is_file', 'file_get_contents', 'hash_file']];

    /**
     * Extensions the child keeps whole: their functions only transform their arguments or touch local
     * files and the local SQLite store. Every function of every other loaded extension is disabled, and
     * an extension the child loads that this list does not know is disabled with it.
     */
    public const PURE_EXTENSIONS = ['Core', 'standard', 'date', 'pcre', 'json', 'hash', 'ctype', 'mbstring', 'SPL', 'tokenizer', 'random', 'Reflection', 'PDO', 'pdo_sqlite', 'filter'];

    /**
     * Functions PHP keeps defined whatever disable_functions says: a namespaced function, and intl
     * functions registered after the setting applies. All are text transforms with no I/O.
     */
    private const UNDISABLEABLE_TEXT_ONLY = ['Dom\\import_simplexml', 'grapheme_str_split', 'normalizer_normalize', 'normalizer_is_normalized', 'normalizer_get_raw_decomposition'];

    /** The network-capable functions of the kept extensions, by exact name or prefix. */
    private const KEPT_NETWORK = [
        'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'proc_close', 'proc_get_status', 'proc_nice', 'proc_terminate', 'dl',
        'fsockopen', 'pfsockopen', 'gethostbyname', 'gethostbynamel', 'gethostbyaddr', 'checkdnsrr', 'getmxrr', 'dns_check_record', 'dns_get_mx',
        'dns_get_record', 'net_get_interfaces', 'mail', 'mb_send_mail', 'stream_wrapper_register', 'stream_register_wrapper', 'stream_wrapper_restore',
        'stream_wrapper_unregister', 'stream_context_set_default', 'putenv', 'header_register_callback',
    ];
    private const KEPT_NETWORK_PREFIXES = ['stream_socket_'];

    private static function root(): string
    {
        return dirname(__DIR__, 4);
    }

    /** @return array{functions:list<string>,classes:list<string>,static:list<string>,parents:list<string>,own:list<string>,store_only:array<string,list<string>>,file_only:array<string,list<string>>} */
    private static function allow(): array
    {
        return ['functions' => self::FUNCTIONS, 'classes' => self::CLASSES, 'static' => self::STATIC, 'parents' => [],
            'own' => ['Funnypot\\App\\Tarpit\\Ssrf\\', 'Funnypot\\App\\Storage\\Ssrf'], 'store_only' => self::STORE_ONLY, 'file_only' => self::FILE_ONLY];
    }

    /** @return list<string> */
    private static function scanned(): array
    {
        return [...glob(self::root() . '/src/App/Tarpit/Ssrf/*.php'), ...glob(self::root() . '/src/App/Storage/Ssrf*.php'), self::root() . '/src/App/Tarpit/Mint/SurfaceExtension.php',
            self::root() . '/src/App/Config/BuildStamp.php'];
    }

    public function test_namespace_calls_only_allowlisted_names(): void
    {
        $files = self::scanned();
        $tokens = 0;
        $all = [];
        foreach ($files as $f) {
            $code = (string) file_get_contents($f);
            $tokens += count(CallScan::tokens($code));
            foreach (CallScan::violations($code, $f, self::allow()) as $v) {
                $all[] = basename($f) . ': ' . $v;
            }
        }
        self::assertGreaterThanOrEqual(35, count($files), 'every file of the namespaces was scanned');
        self::assertGreaterThan(20000, $tokens);
        self::assertSame([], $all);
        $stamp = (string) file_get_contents(self::root() . '/src/App/Config/BuildStamp.php');
        self::assertContains('function: file_get_contents @31', CallScan::violations($stamp, 'Elsewhere.php', self::allow()), 'positive control: the file reads are allowed in the build stamp only');
    }

    public function test_each_forbidden_class_is_flagged(): void
    {
        $fixtures = glob(self::root() . '/tests/Fixtures/ssrf/forbidden/*.php') ?: [];
        self::assertGreaterThanOrEqual(44, count($fixtures));
        foreach ($fixtures as $f) {
            $code = (string) file_get_contents($f);
            self::assertSame(1, preg_match('~// expect: (.+)~', $code, $m), basename($f));
            $v = CallScan::violations($code, $f, self::allow());
            $hit = array_filter($v, static fn (string $x): bool => str_starts_with($x, trim($m[1])));
            self::assertNotEmpty($hit, basename($f) . ' must be flagged as ' . $m[1] . '; got ' . json_encode($v));
        }
    }

    /** @var array<string,list<string>>|null extension => functions, as the child PHP (php -n) loads them */
    private static ?array $childFunctions = null;

    /** @return array<string,list<string>> the child environment's extensions and their functions */
    public static function childFunctions(): array
    {
        if (self::$childFunctions === null) {
            $probe = 'echo json_encode(array_map(static fn ($e) => get_extension_funcs($e) ?: [], array_combine(get_loaded_extensions(), get_loaded_extensions())));';
            $p = proc_open([PHP_BINARY, '-n', '-r', $probe], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
            $out = (string) stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            proc_close($p);
            $decoded = json_decode($out, true);
            self::assertIsArray($decoded, 'the child environment probe ran');
            self::$childFunctions = $decoded;
        }

        return self::$childFunctions;
    }

    /**
     * Every function the child disables, derived per extension: all functions of every loaded extension
     * outside PURE_EXTENSIONS, plus the network-capable functions of the kept ones.
     *
     * @return list<string>
     */
    public static function disabled(): array
    {
        $names = [];
        foreach (self::childFunctions() as $ext => $funcs) {
            if (!in_array($ext, self::PURE_EXTENSIONS, true)) {
                $names = [...$names, ...$funcs];
                continue;
            }
            foreach ($funcs as $fn) {
                if (in_array($fn, self::KEPT_NETWORK, true) || array_filter(self::KEPT_NETWORK_PREFIXES, static fn (string $p): bool => str_starts_with($fn, $p)) !== []) {
                    $names[] = $fn;
                }
            }
        }

        return array_values(array_unique($names));
    }

    /** @return array<string,mixed> */
    private static function child(string $plant = '', int $steps = self::STEPS): array
    {
        $names = self::disabled();
        $env = ['SSRF_DISABLED' => implode(',', $names), 'SSRF_EXTENSIONS' => implode(',', array_keys(self::childFunctions())), 'SSRF_CHILD_PLANT' => $plant,
            'SSRF_CHILD_STEPS' => (string) $steps, 'PATH' => (string) getenv('PATH'), 'TMPDIR' => sys_get_temp_dir()];
        // No php.ini: only the extensions built into the binary load, so shared class clients (redis,
        // openswoole and the like) are absent, and the probe above saw exactly this environment.
        $cmd = [PHP_BINARY, '-n', '-d', 'memory_limit=512M', '-d', 'max_execution_time=120', '-d', 'allow_url_fopen=0', '-d', 'allow_url_include=0',
            '-d', 'ffi.enable=0', '-d', 'sendmail_path=/nonexistent/ssrf-bench', '-d', 'disable_functions=' . implode(',', $names),
            __DIR__ . '/support/no-outbound-child.php'];
        // The child's hit log goes to stderr: send it to a file so neither pipe can fill and block.
        $errFile = (string) tempnam(sys_get_temp_dir(), 'fp0816child');
        $p = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $errFile, 'w']], $pipes, self::root(), $env);
        self::assertIsResource($p);
        $out = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($p);
        $err = (string) file_get_contents($errFile);
        unlink($errFile);
        $lines = array_values(array_filter(explode("\n", $out), static fn (string $l): bool => str_starts_with($l, '{"steps"')));
        $res = json_decode($lines[count($lines) - 1] ?? '', true);
        self::assertIsArray($res, 'child output: ' . substr($out . $err, -800));

        return $res;
    }

    public function test_bench_runs_clean_in_a_child_without_network_functions(): void
    {
        $disabled = self::disabled();
        foreach (['curl_init', 'socket_create', 'odbc_connect', 'odbc_pconnect', 'ldap_connect', 'ftp_connect', 'mysqli_connect', 'pg_connect', 'snmpget', 'fsockopen', 'dns_get_record', 'exec', 'mb_send_mail'] as $fn) {
            if (function_exists($fn) || in_array($fn, array_merge(...array_values(self::childFunctions())), true)) {
                self::assertContains($fn, $disabled, "{$fn} is derived into the disable list");
            }
        }
        $clean = self::child();
        self::assertSame(count($disabled), $clean['checked']);
        self::assertSame([], array_values(array_diff($clean['still_defined'], self::UNDISABLEABLE_TEXT_ONLY)), 'every derived name is really disabled, but for the listed text-only ones');
        self::assertSame([], $clean['unexpected_extensions'], 'the child loaded exactly the probed extensions');
        self::assertFalse($clean['class_clients'], 'no shared class-client extension (redis, openswoole) is loaded');
        self::assertSame(self::STEPS, $clean['steps']);
        self::assertSame(0, $clean['faults']);
        self::assertSame(0, $clean['errors'], (string) ($clean['error'] ?? ''));
        self::assertSame(0, $clean['warnings'], (string) ($clean['last_warning'] ?? ''));
        $inProcess = new SsrfPivotCrawler();
        try {
            self::assertSame($inProcess->run(self::STEPS)['transcript_hash'], $clean['transcript_hash'], 'the child ran the same journey');
        } finally {
            $inProcess->cleanup();
        }
        self::assertSame(1, self::child('curl')['errors'], 'positive control: a planted curl call fails');
        self::assertGreaterThan(0, self::child('url')['warnings'], 'positive control: a planted URL open is refused');
        $stat = self::child('stat');
        self::assertSame([0, 0], [$stat['errors'], $stat['warnings']], 'blind spot, documented: a quiet stat on a URL raises nothing here; check (3) sees it');
    }

    public function test_bench_journey_opens_no_url(): void
    {
        RecordingWrapper::install();
        try {
            file_exists('ftp://x.invalid/a');
            @file_get_contents('http://x.invalid/');
            @unlink('ftp://x.invalid/b');
            @rename('ftp://x.invalid/c', 'ftp://x.invalid/d');
            @mkdir('http://x.invalid/e');
            @rmdir('http://x.invalid/f');
            @touch('ftp://x.invalid/g');
            self::assertSame(['stat ftp://x.invalid/a', 'open http://x.invalid/', 'unlink ftp://x.invalid/b', 'rename ftp://x.invalid/c ftp://x.invalid/d',
                'mkdir http://x.invalid/e', 'rmdir http://x.invalid/f', 'metadata ftp://x.invalid/g'], RecordingWrapper::$log, 'positive controls: the trap records every URL operation');
            RecordingWrapper::$log = [];
            $c = new SsrfPivotCrawler();
            try {
                $r = $c->run(self::STEPS);
            } finally {
                $c->cleanup();
            }
            self::assertSame(self::STEPS, $r['steps']);
            self::assertSame([], RecordingWrapper::$log, 'the journey opened and stat-ed no URL');
        } finally {
            RecordingWrapper::restore();
        }
    }

    public function test_edited_files_add_no_new_calls(): void
    {
        $base = json_decode((string) file_get_contents(self::root() . '/' . self::BASE_FIXTURE), true);
        self::assertIsArray($base);
        self::assertGreaterThanOrEqual(15, count($base['files']), 'every edited file has a recorded base');
        $checked = 0;
        foreach ($base['files'] as $file => $sets) {
            $now = CallScan::extract((string) file_get_contents(self::root() . '/' . $file));
            foreach (['calls', 'new', 'static', 'extends'] as $kind) {
                $gained = array_values(array_diff($now[$kind], $sets[$kind], self::DELTA[$kind]));
                self::assertSame([], $gained, "{$file} gained {$kind} not in the base or the listed delta");
                $checked += count($now[$kind]);
            }
        }
        self::assertGreaterThan(300, $checked, 'the pin read the files');
    }

    public function test_the_call_pin_sees_a_planted_call(): void
    {
        $planted = CallScan::extract("<?php\nnamespace A;\nuse B\\C;\nfunction f() { curl_init(); new C(); \\D\\E::open(); }\nclass X extends \\SoapClient {}\n");
        self::assertContains('curl_init', $planted['calls']);
        self::assertContains('B\\C', $planted['new']);
        self::assertContains('D\\E::open', $planted['static']);
        self::assertContains('SoapClient', $planted['extends']);
        unset($planted);
        self::assertTrue(class_exists(MintHarness::class));
    }
}
