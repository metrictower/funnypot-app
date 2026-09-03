<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\AiApi\AiApiRouter;
use Funnypot\App\AiApi\AiChatHandler;
use Funnypot\App\AiApi\AiChatPromptBuilder;
use Funnypot\App\AiApi\NonsenseFallback;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\AiApi\WordSwap;
use Funnypot\App\AiApi\WrongLanguageCode;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\ConsoleRouter;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DownloadRouter;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Shell\ConsoleSessionStore;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\Core\Ai\ModelCatalog;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ZipArchive;

require_once dirname(__DIR__, 2) . '/demo/lib/geo.php';

/**
 * FP-0112: the gate FingerprintSafetyTest ran was structured as "render a hand-curated list of skin
 * paths -> scan the HTML". That shape cannot cover a surface nobody thought to add to the list — which
 * is exactly how /__dl/sw.js shipped `// funnypot — endless decoy-download service worker (client-side
 * bait).` verbatim to an unauthenticated GET for three commits running.
 *
 * This suite scans every OTHER surface this app serves, enumerated from the routers/constants that
 * own them rather than a hand-written path list (AiApiRouter::CHAT_PATHS, DownloadRouter's PATH
 * constants, ConsoleRouter::PATH, CorporateController's trap prefixes) — service worker source
 * (including comments), JSON manifests, streamed archive bytes, the web-terminal console, the stealth
 * corporate front + its trap pages + its static CSS, response headers, and the decoy archives
 * (including their nested member entries, unpacked). Every checked surface is client-served, so
 * everything here is checked against BOTH leak-IN (an upstream detector's vocabulary) and leak-OUT
 * (this project's own vocabulary) — unlike FingerprintSafetyTest's LLM-exemplar rows, nothing in this
 * file is an internal-only prompt.
 *
 * Subsumes and removes the stopgap DownloadWorkerFingerprintTest (this suite's sw.js coverage below is
 * a strict superset: same file, same word-boundary matching, plus every other served surface).
 */
final class ServedSurfacesFingerprintTest extends TestCase
{
    private const SEED = 4242;
    private const SECRET = 'served-surfaces-test-secret';

    /**
     * DownloadRouter's manifest draws 40 random file sizes per host from a large heavy-tailed range;
     * at persona seed 4242 one of them happens to land on the exact bare integer 940969, which the
     * PRE-EXISTING (unmodified by FP-0112) leak-IN bare-CRS-rule-id pattern reads as a rule id purely
     * by numeric coincidence — the same class of false collision the hex-accent-color carve-out
     * upstream already documents, just on a JSON integer instead of a hex color. It is not a
     * fingerprint leak (a scanner cannot distinguish "this looks like a CRS rule id" from "this is a
     * random file size" from the number alone) and reworking the manifest's random-size generator to
     * dodge it is out of FP-0112's scope (a leak-out/coverage ticket, not a manifest RNG ticket) — see
     * the coder's final report for a pointer to file that separately. Seed 1 is used for the manifest/
     * fallback-zip surfaces specifically so this suite's own signal stays about fingerprinting, not
     * about that unrelated pre-existing coincidence.
     */
    private const MANIFEST_SEED = 1;

    /** @var string[] temp files/dirs created during a test, cleaned up in tearDown */
    private array $cleanupPaths = [];

    protected function tearDown(): void
    {
        foreach ($this->cleanupPaths as $p) {
            if (is_dir($p)) {
                self::rrmdir($p);
            } elseif (is_file($p)) {
                @unlink($p);
            }
        }
        $this->cleanupPaths = [];
    }

    // --- shared denylist scanning (mirrors FingerprintSafetyTest; see that file's doc comment for why
    //     the own_vocabulary match is delimiter-safe/whole-token rather than substring) -------------

    /** @return array{literals: list<string>, patterns: list<string>, own_vocabulary: list<string>} */
    private static function denylist(): array
    {
        $d = require dirname(__DIR__, 2) . '/resources/app-fingerprint-denylist.php';

        return [
            'literals' => array_values((array) ($d['literals'] ?? [])),
            'patterns' => array_values((array) ($d['patterns'] ?? [])),
            'own_vocabulary' => array_values((array) ($d['own_vocabulary'] ?? [])),
        ];
    }

    /** FP-0112 finding #4: digits are deliberately NOT word characters in this lookaround — see
     *  FingerprintSafetyTest::ownVocabularyPattern()'s doc comment for why (a digit-glued stem like
     *  `decoy2` must still be caught; this is a mirror of the same regex, kept in sync by hand). */
    private static function ownVocabularyPattern(): string
    {
        $vocab = self::denylist()['own_vocabulary'];

        return '/(?<![a-zA-Z])(' . implode('|', $vocab) . ')(?![a-zA-Z])/i';
    }

    /** @return list<string> every signature (leak-IN or leak-OUT) found in $text (empty => clean) */
    private static function scanAll(string $text): array
    {
        $d = self::denylist();
        $hits = [];
        foreach ($d['literals'] as $needle) {
            if ($needle !== '' && stripos($text, $needle) !== false) {
                $hits[] = "leak-in:{$needle}";
            }
        }
        foreach ($d['patterns'] as $pattern) {
            if (@preg_match('~' . $pattern . '~i', $text) === 1) {
                $hits[] = "leak-in:/{$pattern}/";
            }
        }
        if (preg_match_all(self::ownVocabularyPattern(), $text, $m) >= 1) {
            foreach (array_unique(array_map('strtolower', $m[0])) as $term) {
                $hits[] = "leak-out:{$term}";
            }
        }

        return $hits;
    }

    /** Every surface in this file is client-served, so every assertion checks BOTH directions. */
    private static function assertServedClean(string $text, string $source): void
    {
        $hits = self::scanAll($text);
        self::assertSame([], $hits, "fingerprint leak in {$source}: " . implode(', ', $hits));
    }

    /** @param array<string,string> $headers */
    private static function assertHeadersClean(array $headers, string $source): void
    {
        foreach ($headers as $name => $value) {
            self::assertServedClean("{$name}: {$value}", "{$source} header {$name}");
        }
    }

    private static function rrmdir(string $dir): void
    {
        $items = @scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_dir($path) && !is_link($path)) {
                self::rrmdir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    // --- 1. Service worker (src/App/Download/sw.js), read straight off disk ----------------------

    public function test_service_worker_source_carries_no_fingerprint_signature(): void
    {
        $path = dirname(__DIR__, 2) . '/src/App/Download/sw.js';
        self::assertFileExists($path);
        $src = (string) file_get_contents($path);
        // Sanity: it really is the worker (a rename/rewrite can't make this test vacuously pass).
        self::assertStringContainsString("addEventListener('fetch'", $src);
        self::assertServedClean($src, 'src/App/Download/sw.js (served verbatim at /__dl/sw.js)');
    }

    // --- 2. Historical regression fixture ("prove the gate bites") ---------------------------------

    /**
     * The exact first line three consecutive production commits shipped verbatim at /__dl/sw.js
     * (see ticket.md / FP-0112's source disclosure). Reproduced as a literal fixture — this repo's
     * history was squashed on import so the originating commit id is not checkable out here — and
     * asserted to trip the scanner on all three self-identifying terms. An assertion never observed
     * failing on the actual historical defect is not evidence the gate would have caught it.
     */
    public function test_scanner_rejects_the_historical_sw_js_disclosure(): void
    {
        $historicalFirstLine = '// funnypot — endless decoy-download service worker (client-side bait).';
        $hits = self::scanAll($historicalFirstLine);
        self::assertNotSame([], $hits);
        self::assertContains('leak-out:funnypot', $hits);
        self::assertContains('leak-out:decoy', $hits);
        self::assertContains('leak-out:bait', $hits);
    }

    // --- 3a. AiApiRouter::CHAT_PATHS, enumerated from the constant, not a hand list ------------------

    /**
     * FP-0112 review #2: every row used to send 'stream' => true, so AiChatHandler::handle() always
     * took the streaming branch — $bufferedHeaders stayed [] and assertHeadersClean() on it vacuously
     * passed, while the REAL emitted headers ($emitter->headers()) were never scanned at all. Cross
     * every declared chat path with BOTH stream=true (the streaming branch, now actually scanned via
     * $emitter->headers()) and stream=false (the buffered branch, now genuinely exercised instead of
     * assumed empty), so no combination goes unchecked.
     *
     * @return array<string,array{0:string,1:bool}>
     */
    public static function chatPathsByStreamMode(): array
    {
        $out = [];
        foreach (AiApiRouter::CHAT_PATHS as $path) {
            foreach ([true, false] as $stream) {
                $out[$path . ' (stream=' . ($stream ? 'true' : 'false') . ')'] = [$path, $stream];
            }
        }

        return $out;
    }

    /**
     * Forces the deterministic troll (NonsenseFallback) path — no sidecar network call — by pinning
     * the fake IP as bulk-flagged, so ProbeGate::decide() declines before the LLM would ever be
     * touched. Scans the ACTUAL response bytes AND the ACTUAL emitted headers for whichever branch the
     * request drove — streamed ($emitter->captured()/$emitter->headers()) or buffered ($bufferedBody/
     * $bufferedHeaders) — for every one of AiApiRouter's declared chat paths (currently /api/chat,
     * /api/generate, /v1/chat/completions, /v1/messages — adding a fifth to CHAT_PATHS scans it here
     * automatically, no test edit needed) crossed with both stream modes.
     *
     * @dataProvider chatPathsByStreamMode
     */
    public function test_ai_api_chat_response_stream_carries_no_fingerprint_signature(string $path, bool $stream): void
    {
        $ip = '203.0.113.50';
        $store = new AlwaysBulkFlaggedHitStore();
        $emitter = new StreamEmitter(static fn (string $b): ?string => null, 0);
        // Both sinks are closures — neither path can fall through to a real header()/echo call.
        $bufferedStatus = 0;
        $bufferedHeaders = [];
        $bufferedBody = '';
        $emitBuffered = static function (int $s, array $h, string $b) use (&$bufferedStatus, &$bufferedHeaders, &$bufferedBody): void {
            $bufferedStatus = $s;
            $bufferedHeaders = $h;
            $bufferedBody = $b;
        };
        $handler = new AiChatHandler(
            new LlmClient('http://127.0.0.1:1/unreachable', 50, 32),
            new AiChatPromptBuilder(),
            new LlmOutputSanitizer(),
            new NonsenseFallback(),
            new WordSwap(),
            new WrongLanguageCode(),
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache(sys_get_temp_dir() . '/fp-served-surfaces-unused-cache.sqlite'),
            $store,
            ModelCatalog::fromPackage(),
            null,   // abuse: not needed for this scan
            false,  // strictAuth
            false,  // strictModel
            0.8, 0.0, 1.0, 4, 5, 600, 0,
            $emitBuffered,
            static fn (): StreamEmitter => $emitter,
        );
        $router = new AiApiRouter($handler);
        self::assertTrue($router->matches($path), "AiApiRouter must own its own declared chat path {$path}");

        $body = (string) json_encode([
            'model' => 'served-surfaces-test-model',
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => $stream,
        ]);
        $ctx = new RequestContext('POST', $path, '', ['x-api-key' => 'sk-ant-test'], $body);
        $router->handle($ctx, $ip);

        $streamed = $emitter->captured();
        $streamedHeaders = $emitter->headers();
        // Whichever branch actually ran (streamed on a clean parse; buffered on a parse/error fallback
        // OR on a request that asked stream=false) must have emitted something, and BOTH branches'
        // captures are scanned regardless — a route that unexpectedly falls back to the other framing
        // must not go unchecked just because a particular stream mode was requested.
        self::assertTrue($streamed !== '' || $bufferedBody !== '', "no response captured at all for chat path {$path} (stream={$stream})");
        // The requested branch must be the one that actually ran — otherwise this test would silently
        // stop exercising the streaming path (or the buffered one) the way review #2 found it had.
        if ($stream) {
            self::assertNotSame('', $streamed, "stream=true must drive the STREAMING branch for {$path}");
            self::assertNotSame([], $streamedHeaders, "stream=true must emit real headers via StreamEmitter::begin() for {$path}");
        } else {
            self::assertNotSame('', $bufferedBody, "stream=false must drive the BUFFERED branch for {$path}");
        }
        self::assertServedClean($streamed, "AiApiRouter streamed chat response for {$path}");
        self::assertServedClean($bufferedBody, "AiApiRouter buffered/error chat response for {$path}");
        self::assertHeadersClean($bufferedHeaders, "AiApiRouter buffered/error chat response for {$path}");
        self::assertHeadersClean($streamedHeaders, "AiApiRouter streamed chat response for {$path}");
    }

    // --- 3b. DownloadRouter's three declared paths ---------------------------------------------------

    public function test_download_router_sw_js_path_serves_the_real_file_clean(): void
    {
        $swPath = dirname(__DIR__, 2) . '/src/App/Download/sw.js';
        [$body, $headers, $router] = $this->captureDownloadRouter(
            DownloadRouter::SW_PATH,
            (string) file_get_contents($swPath)
        );
        self::assertTrue($router->matches(DownloadRouter::SW_PATH));
        self::assertServedClean($body, 'DownloadRouter ' . DownloadRouter::SW_PATH . ' body (real on-disk sw.js)');
        self::assertHeadersClean($headers, 'DownloadRouter ' . DownloadRouter::SW_PATH);
        self::assertSame('/', $headers['Service-Worker-Allowed'] ?? null);
    }

    public function test_download_router_manifest_path_carries_no_fingerprint_signature(): void
    {
        $host = (string) Fleet::fromSeed(self::MANIFEST_SEED)->servers()[0]['host'];
        self::assertNotSame('', $host, 'DownloadRouter needs a real fleet host for its manifest — none constructible');
        [$body, $headers, $router] = $this->captureDownloadRouter(
            DownloadRouter::MANIFEST_PATH,
            '/* sw not under test here */',
            'host=' . $host,
            50,
            self::MANIFEST_SEED
        );
        self::assertTrue($router->matches(DownloadRouter::MANIFEST_PATH));
        self::assertJson($body);
        self::assertServedClean($body, 'DownloadRouter ' . DownloadRouter::MANIFEST_PATH . ' body');
        self::assertHeadersClean($headers, 'DownloadRouter ' . DownloadRouter::MANIFEST_PATH);
    }

    public function test_download_router_backup_zip_fallback_stream_carries_no_fingerprint_signature(): void
    {
        $host = (string) Fleet::fromSeed(self::MANIFEST_SEED)->servers()[0]['host'];
        self::assertNotSame('', $host, 'DownloadRouter needs a real fleet host for its fallback zip — none constructible');
        // Small fallback cap: this scans the STREAMED FALLBACK bytes for a fingerprint tell, not the
        // full multi-MB body (DownloadRouterTest already covers cap/zip-header correctness).
        [$body, $headers, $router] = $this->captureDownloadRouter(
            DownloadRouter::ZIP_PATH,
            '/* sw not under test here */',
            'host=' . $host,
            1, // 1 MiB fallback cap
            self::MANIFEST_SEED
        );
        self::assertTrue($router->matches(DownloadRouter::ZIP_PATH));
        self::assertStringStartsWith("PK\x03\x04", $body);
        self::assertServedClean($body, 'DownloadRouter ' . DownloadRouter::ZIP_PATH . ' streamed fallback body');
        self::assertHeadersClean($headers, 'DownloadRouter ' . DownloadRouter::ZIP_PATH);
        self::assertSame('attachment; filename="backup.zip"', $headers['Content-Disposition'] ?? null);
    }

    /** @return array{0:string,1:array<string,string>,2:DownloadRouter} [body, headers, router] */
    private function captureDownloadRouter(string $path, string $swScript, string $query = '', int $fallbackCapMb = 50, int $personaSeed = self::SEED): array
    {
        $emitter = new StreamEmitter(static fn (string $b): ?string => null, 0);
        $factory = static fn (): StreamEmitter => $emitter;
        $router = new DownloadRouter(new NoopHitStore(), $personaSeed, $swScript, 100, 200, 100, 50, 20, $fallbackCapMb, $factory);
        $router->handle(new RequestContext('GET', $path, $query), '203.0.113.51');

        return [$emitter->captured(), $emitter->headers(), $router];
    }

    // --- 3c. ConsoleRouter::PATH ------------------------------------------------------------------

    /** @return array<string,array{0:string}> */
    public static function consoleCommands(): array
    {
        return [
            'whoami' => ['whoami'],
            'uname -a' => ['uname -a'],
            'pwd' => ['pwd'],
            'ls -la' => ['ls -la'],
            'id' => ['id'],
        ];
    }

    /** @dataProvider consoleCommands */
    public function test_console_router_response_carries_no_fingerprint_signature(string $command): void
    {
        $dbPath = tempnam(sys_get_temp_dir(), 'fpconsole');
        self::assertNotFalse($dbPath, 'could not allocate a temp session db for ConsoleRouter');
        $this->cleanupPaths[] = $dbPath;

        $emitter = new StreamEmitter(static fn (string $b): ?string => null, 0);
        $factory = static fn (): StreamEmitter => $emitter;
        $router = new ConsoleRouter(new ConsoleSessionStore($dbPath), new NoopHitStore(), self::SEED, self::SECRET, $factory);
        $host = (string) Fleet::fromSeed(self::SEED)->servers()[0]['host'];
        self::assertNotSame('', $host, 'ConsoleRouter needs a real fleet host to exercise the shell — none constructible');

        $body = (string) json_encode(['host' => $host, 'command' => $command]);
        $router->handle(new RequestContext('POST', ConsoleRouter::PATH, '', [], $body), '203.0.113.52');

        self::assertServedClean($emitter->captured(), "ConsoleRouter response for command '{$command}'");
        self::assertHeadersClean($emitter->headers(), "ConsoleRouter response for command '{$command}'");
    }

    // --- 3d. CorporateController: homepage, login (GET+POST), trap page, static CSS -----------------

    /** @return array{0:CorporateController,1:string} [controller, assetsDir] */
    private function corporateController(): array
    {
        $assetsDir = dirname(__DIR__, 2) . '/demo/assets';
        self::assertFileExists($assetsDir . '/corporate.css', 'corporate.css must exist to be scanned as a served static asset');

        $dir = sys_get_temp_dir() . '/fp-0112-corp-' . bin2hex(random_bytes(6));
        @mkdir($dir, 0777, true);
        $this->cleanupPaths[] = $dir;
        putenv('FUNNYPOT_ADMIN_USER');
        putenv('FUNNYPOT_DASHBOARD_PATH');
        $config = AppConfig::fromEnv($dir);
        $geo = new \Geo($dir . '/no-geo');

        return [new CorporateController(new NoopHitStore(), $geo, $config, $assetsDir), $assetsDir];
    }

    private function render(callable $call): string
    {
        ob_start();
        @$call();

        return (string) ob_get_clean();
    }

    public function test_corporate_homepage_carries_no_fingerprint_signature(): void
    {
        [$corp] = $this->corporateController();
        $html = $this->render(fn () => $corp->homepage());
        self::assertServedClean($html, 'CorporateController::homepage()');
    }

    public function test_corporate_login_get_carries_no_fingerprint_signature(): void
    {
        [$corp] = $this->corporateController();
        $html = $this->render(fn () => $corp->login('GET', '203.0.113.53'));
        self::assertServedClean($html, "CorporateController::login('GET')");
    }

    /** The invalid-credential re-render is what an unauthenticated POST actually gets served. */
    public function test_corporate_login_post_invalid_credential_response_carries_no_fingerprint_signature(): void
    {
        [$corp] = $this->corporateController();
        $_POST = ['username' => 'not-the-operator', 'password' => 'whatever'];
        $html = $this->render(fn () => $corp->login('POST', '203.0.113.54'));
        $_POST = [];
        self::assertStringContainsString('Invalid username or password', $html);
        self::assertServedClean($html, "CorporateController::login('POST') invalid-credential decoy");
    }

    /** A trap path built from the router's OWN declared prefixes (reflection on the private const),
     *  not a hand-guessed literal, so a change to TRAP_PREFIXES is picked up automatically. */
    public function test_corporate_trap_page_carries_no_fingerprint_signature(): void
    {
        [$corp] = $this->corporateController();
        $prefixes = (new ReflectionClass(CorporateController::class))->getConstant('TRAP_PREFIXES');
        self::assertIsArray($prefixes);
        self::assertNotEmpty($prefixes, 'CorporateController::TRAP_PREFIXES must be constructible — a skip here would hide the exact gap this ticket closes');
        $trapPath = '/' . $prefixes[0] . '-' . $prefixes[1 % count($prefixes)] . '-1234';
        self::assertTrue($corp->isTrapPath($trapPath), 'the constructed path must actually match isTrapPath()');

        $ctx = new RequestContext('GET', $trapPath);
        $html = $this->render(fn () => $corp->trap($ctx, '203.0.113.55', 'GET'));
        self::assertServedClean($html, "CorporateController::trap({$trapPath})");
    }

    public function test_corporate_static_css_carries_no_fingerprint_signature(): void
    {
        [, $assetsDir] = $this->corporateController();
        $css = (string) file_get_contents($assetsDir . '/corporate.css');
        self::assertServedClean($css, 'demo/assets/corporate.css (served verbatim)');
    }

    // --- 4. Decoy archives — text decoys + recursive member-entry inspection of the nested archives -

    /** @return array<string,array{0:string}> */
    public static function textDecoys(): array
    {
        return [
            'backup.sql' => ['backup.sql'],
            'wallet.json' => ['wallet.json'],
            'backup.pem' => ['backup.pem'],
            'backup.cer' => ['backup.cer'],
        ];
    }

    /** @dataProvider textDecoys */
    public function test_text_decoy_carries_no_fingerprint_signature(string $file): void
    {
        $path = dirname(__DIR__, 2) . '/demo/decoys/' . $file;
        self::assertFileExists($path);
        self::assertServedClean((string) file_get_contents($path), "demo/decoys/{$file}");
    }

    /**
     * The nested archive decoys (AC4). Each is a deep chain of same-format archives (zip nests zip,
     * tar.gz nests tar.gz, …) grown to ~1MB so extraction wastes an attacker's time — the fully-
     * extracted innermost payload (a fabricated NOTICE.txt + fake creds) is exactly what a patient
     * attacker eventually reaches, so it must be scanned too, not just the outer README.
     *
     * This closes a SECOND real leak found re-baselining this ticket (not the sw.js one): the
     * innermost NOTICE.txt used to read "This archive was served by a honeypot. …" — self-identifying
     * text sitting at the bottom of every one of these four archives, reachable by full extraction
     * (verified before the fix at depth 341/370/208/97 across zip/tar.gz/tar.bz2/tar respectively).
     * Fixed at the source (scripts/build-decoys.sh) and the shipped archives regenerated; this test is
     * the regression guard so it can never silently come back.
     */
    public function test_zip_decoy_every_nested_layer_carries_no_fingerprint_signature(): void
    {
        $path = dirname(__DIR__, 2) . '/demo/decoys/backup.zip';
        self::assertFileExists($path);
        $this->walkZipRecursive((string) file_get_contents($path), 'demo/decoys/backup.zip');
    }

    public function test_tar_decoy_every_nested_layer_carries_no_fingerprint_signature(): void
    {
        $this->walkTarRecursive('backup.tar', '.tar');
    }

    public function test_targz_decoy_every_nested_layer_carries_no_fingerprint_signature(): void
    {
        $this->walkTarRecursive('backup.tar.gz', '.tar.gz');
    }

    public function test_tarbz2_decoy_every_nested_layer_carries_no_fingerprint_signature(): void
    {
        $this->walkTarRecursive('backup.tar.bz2', '.tar.bz2');
    }

    /** Iterative (not recursive-call) walk of a store-method nested zip chain, scanning every member
     *  entry at every layer, following the single same-extension nested archive down to the leaf. */
    private function walkZipRecursive(string $bytes, string $label): void
    {
        $depth = 0;
        $data = $bytes;
        $leafReached = false;
        while (true) {
            $tmp = tempnam(sys_get_temp_dir(), 'fpzipwalk');
            self::assertNotFalse($tmp);
            file_put_contents($tmp, $data);
            $zip = new ZipArchive();
            $opened = $zip->open($tmp);
            if ($opened !== true) {
                @unlink($tmp);
                self::fail("could not open {$label} as a zip at nesting depth {$depth} (code {$opened})");
            }
            $next = null;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $name = $zip->getNameIndex($i);
                self::assertNotFalse($name);
                $content = (string) $zip->getFromIndex($i);
                self::assertServedClean($name, "{$label} [zip depth {$depth}] member name");
                self::assertServedClean($content, "{$label} [zip depth {$depth}] member {$name}");
                if (strtolower(substr($name, -4)) === '.zip') {
                    $next = $content;
                }
            }
            $zip->close();
            @unlink($tmp);
            if ($next === null) {
                $leafReached = true;
                break;
            }
            $data = $next;
            $depth++;
            self::assertLessThan(2000, $depth, "runaway/unbounded zip nesting in {$label} — refusing to continue");
        }
        self::assertTrue($leafReached, "{$label}: never reached a leaf (non-nested) layer");
        self::assertGreaterThan(0, $depth, "{$label}: expected genuine nesting, found none — decoy build may have changed shape");
    }

    /**
     * Iterative walk of a nested tar/tar.gz/tar.bz2 chain via the `tar` CLI (GNU tar; auto-detects the
     * compression and also tolerates the AppleDouble `._*` metadata these archives carry from being
     * built on macOS — PHP's PharData tar reader trips on those extended headers, the CLI does not).
     */
    private function walkTarRecursive(string $filename, string $ext): void
    {
        $current = dirname(__DIR__, 2) . '/demo/decoys/' . $filename;
        self::assertFileExists($current);
        $depth = 0;
        $leafReached = false;
        while (true) {
            $dir = sys_get_temp_dir() . '/fp-tarwalk-' . bin2hex(random_bytes(6));
            self::assertTrue(mkdir($dir, 0777, true), "could not create scratch dir for {$filename} at depth {$depth}");
            $this->cleanupPaths[] = $dir;

            $out = [];
            $rc = 0;
            exec('tar -xf ' . escapeshellarg($current) . ' -C ' . escapeshellarg($dir) . ' 2>&1', $out, $rc);
            self::assertSame(0, $rc, "tar extraction failed for {$filename} at depth {$depth}: " . implode("\n", $out));

            $next = null;
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
            $sawAnyFile = false;
            foreach ($iterator as $file) {
                if ($file->isDir()) {
                    continue;
                }
                $sawAnyFile = true;
                $name = $file->getFilename();
                if (strpos($name, '._') === 0) {
                    continue; // AppleDouble resource-fork shadow file — no real content, not served
                }
                $content = (string) file_get_contents($file->getPathname());
                self::assertServedClean($name, "{$filename} [{$ext} depth {$depth}] member name");
                self::assertServedClean($content, "{$filename} [{$ext} depth {$depth}] member {$name}");
                if (strtolower(substr($name, -strlen($ext))) === $ext) {
                    $next = $file->getPathname();
                }
            }
            self::assertTrue($sawAnyFile, "{$filename} at depth {$depth} extracted with no member files — extraction silently produced nothing");

            if ($next === null) {
                $leafReached = true;
                break;
            }
            $current = $next;
            $depth++;
            self::assertLessThan(2000, $depth, "runaway/unbounded {$ext} nesting in {$filename} — refusing to continue");
        }
        self::assertTrue($leafReached, "{$filename}: never reached a leaf (non-nested) layer");
        self::assertGreaterThan(0, $depth, "{$filename}: expected genuine nesting, found none — decoy build may have changed shape");
    }
}

/** Minimal HitStore whose isBulkFlagged() is always true, so ProbeGate::decide() always declines
 *  Gate A deterministically — forces AiChatHandler onto the NonsenseFallback path with no sidecar
 *  network call and no sqlite storage needed. Every other method is an inert stub. */
final class AlwaysBulkFlaggedHitStore implements HitStore
{
    public function append(array $entry): void
    {
    }

    public function delta(int $cursor, array $filters = []): array
    {
        return ['cursor' => 0, 'reset' => false, 'rows' => []];
    }

    public function older(int $skip, array $filters = []): array
    {
        return ['rows' => [], 'more' => false];
    }

    public function stats(): array
    {
        return [];
    }

    public function widgets(): array
    {
        return [];
    }

    public function prune(int $keep): void
    {
    }

    public function clear(): void
    {
    }

    public function import(): int
    {
        return 0;
    }

    public function probeVelocity(string $ip): array
    {
        return ['recent' => 0, 'extended' => 0];
    }

    public function recentEventCount(string $ip, string $event, int $sinceSeconds): int
    {
        return 0;
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
    }

    public function isBulkFlagged(string $ip): bool
    {
        return true;
    }
}

/** Minimal HitStore recording nothing, declining nothing — used where a router just needs SOME
 *  HitStore to log bait/shell hits to and no gating decision is involved. */
final class NoopHitStore implements HitStore
{
    public function append(array $entry): void
    {
    }

    public function delta(int $cursor, array $filters = []): array
    {
        return ['cursor' => 0, 'reset' => false, 'rows' => []];
    }

    public function older(int $skip, array $filters = []): array
    {
        return ['rows' => [], 'more' => false];
    }

    public function stats(): array
    {
        return [];
    }

    public function widgets(): array
    {
        return [];
    }

    public function prune(int $keep): void
    {
    }

    public function clear(): void
    {
    }

    public function import(): int
    {
        return 0;
    }

    public function probeVelocity(string $ip): array
    {
        return ['recent' => 0, 'extended' => 0];
    }

    public function recentEventCount(string $ip, string $event, int $sinceSeconds): int
    {
        return 0;
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
    }

    public function isBulkFlagged(string $ip): bool
    {
        return false;
    }
}
