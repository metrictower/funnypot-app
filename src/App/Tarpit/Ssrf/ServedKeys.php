<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\DirectiveRenderer;

/**
 * Recognises a key this honeypot served, from the generators that serve it rather than from a hand
 * list, so every leaked key leads into the credential gateways' loop.
 *
 * Two families are checked directly: the persona's own AWS and Stripe keys (served by many core fakes),
 * and core's per-source keys, re-rendered through core's own DirectiveRenderer with the engine's render
 * seed for this request's address, crc32("<ip>|<salt>"). Everything the app's generators serve
 * (settings.py at the configured cap, the rabbit-hole log, the hostile JSON, the admin panel's
 * secrets, the shells' /root files) is looked up in the keyed-hash index KeyIndexBuilder fills.
 * Documentation example keys and placeholder runs are never recognised: their shape is public.
 *
 * A credential reference is built when a URL is saved, from the live request, and stored with it; it
 * holds no credential byte.
 */
final class ServedKeys
{
    public const CORE_DIRECTIVES = ['ASIA{{fake.imdsak:hexupper:16}}', 'sk_live_{{fake.stripe_sk:hex:24}}', 'sk_live_{{fake.wcsk:hex:24}}'];
    public const CORE_TOKEN = '{{fake.imdstoken:b64:100}}';
    public const PERSONA_FIELDS = ['cloud.aws.accessKeyId', 'cloud.stripe.secretKey'];

    /**
     * Every app source file that holds a key-shaped literal or calls a key generator, and what it is:
     * a family this class or the index recognises, or not_served with the reason.
     */
    public const SOURCE_FILES = [
        'src/App/Tarpit/ConfigDump.php' => 'configdump',
        'src/App/Tarpit/InertSecret.php' => 'generator: every family that renders a key calls it',
        'src/App/Tarpit/LogRabbitHole.php' => 'log',
        'src/App/Tarpit/HostileFormat.php' => 'hostile',
        'src/App/Render/Fake/FakeSecrets.php' => 'bait',
        'src/Shell/Fs/PinnedNodes.php' => 'shell',
        'src/App/Llm/LlmOutputSanitizer.php' => 'not_served: scan patterns, not values',
        'src/App/Tarpit/Ssrf/ServedKeys.php' => 'not_served: recognition patterns',
        'src/App/Tarpit/Ssrf/KeyIndexBuilder.php' => 'not_served: recognition patterns',
        'demo/index.php' => 'persona: the LLM sanitizer exemption list is the persona key',
    ];

    /**
     * Core key sources the app leaves dormant. Core's mock-auth decoy tables serve AWS and test-mode
     * Stripe rows only once a decoy session key is set, which the app's core config never does; enabling
     * mock-auth must add them as a family first.
     */
    public const CORE_DORMANT = ['Funnypot\\Core\\Support\\Fake\\FakeRecords::apiKeys' => 'not_served: mock-auth tables, dormant while decoySessionKey is unset'];

    private DirectiveRenderer $renderer;

    /** @var array<string,array<string,string>> per-address rendered core keys */
    private array $rendered = [];

    /** @var list<string>|null */
    private ?array $persona = null;

    public function __construct(private int $personaSeed, private string $renderSalt, private KeyIndexView $index)
    {
        $this->renderer = new DirectiveRenderer($personaSeed);
    }

    public function index(): KeyIndexView
    {
        return $this->index;
    }

    /** aws, asia or stripe, or null for a value of no key shape. */
    public static function kindOf(string $value): ?string
    {
        return match (true) {
            preg_match('/\AAKIA[0-9A-Z]{16}\z/', $value) === 1 => 'aws',
            preg_match('/\AASIA[0-9A-Z]{16}\z/', $value) === 1 => 'asia',
            preg_match('/\A[sr]k_(?:live|test)_[0-9A-Za-z]{10,99}\z/', $value) === 1 => 'stripe',
            default => null,
        };
    }

    /** A key whose shape is public knowledge: a documentation example, or one character repeated. */
    public static function placeholder(string $value): bool
    {
        if (stripos($value, 'example') !== false) {
            return true;
        }
        $body = (string) preg_replace('/\A(?:AKIA|ASIA|[sr]k_(?:live|test)_)/', '', $value);

        return $body === '' || count(array_unique(str_split($body))) <= 2;
    }

    /** @return array<string,string> directive => value, rendered for an address */
    public function coreKeys(string $clientIp): array
    {
        if (!isset($this->rendered[$clientIp])) {
            $seed = crc32(($clientIp !== '' ? $clientIp : 'anon') . '|' . $this->renderSalt);
            $out = [];
            foreach ([...self::CORE_DIRECTIVES, self::CORE_TOKEN] as $d) {
                $out[$d] = $this->renderer->render($d, [], $seed);
            }
            $this->rendered = [$clientIp => $out];
        }

        return $this->rendered[$clientIp];
    }

    public function sessionToken(string $clientIp): string
    {
        return $this->coreKeys($clientIp)[self::CORE_TOKEN];
    }

    /** @return list<string> */
    public function personaKeys(): array
    {
        if ($this->persona === null) {
            $p = PersonaIdentity::fromSeed($this->personaSeed);
            $this->persona = array_values(array_filter(array_map(static fn (string $f): string => (string) $p->field($f), self::PERSONA_FIELDS)));
        }

        return $this->persona;
    }

    /** The family that recognises a value directly (persona or core_render), or null. */
    public function direct(string $value, string $clientIp): ?string
    {
        if (self::placeholder($value)) {
            return null;
        }
        foreach ($this->personaKeys() as $k) {
            if (hash_equals($k, $value)) {
                return 'persona';
            }
        }
        foreach (self::CORE_DIRECTIVES as $d) {
            if (hash_equals($this->coreKeys($clientIp)[$d], $value)) {
                return 'core_render';
            }
        }

        return null;
    }

    /** Whether a value is a key this honeypot served (any family), for this request's address. */
    public function recognise(string $value, string $clientIp): ?string
    {
        $kind = self::kindOf($value);
        if ($kind === null || self::placeholder($value)) {
            return null;
        }
        $direct = $this->direct($value, $clientIp);
        if ($direct !== null) {
            return $direct;
        }

        return $this->index->contains($kind, $value) ? 'indexed' : null;
    }

    /**
     * The credential a fetch URL carries, as a stored reference, or null when it carries none: a
     * presigned query (X-Amz-Credential or AWSAccessKeyId) or a key in the userinfo.
     *
     * @return array<string,mixed>|null
     */
    public function reference(Target $t, string $clientIp): ?array
    {
        $q = TargetParser::queryPairs($t->query);
        $key = null;
        $w = 'query';
        $d = 0;
        $x = 0;
        $token = null;
        if (isset($q['x-amz-credential'])) {
            $key = explode('/', $q['x-amz-credential'], 2)[0];
            $d = self::amzDate($q['x-amz-date'] ?? '');
            $x = isset($q['x-amz-expires']) && ctype_digit($q['x-amz-expires']) ? min(604800, (int) $q['x-amz-expires']) : 0;
            $token = $q['x-amz-security-token'] ?? null;
        } elseif (isset($q['awsaccesskeyid'])) {
            $key = $q['awsaccesskeyid'];
            $token = $q['securitytoken'] ?? ($q['x-amz-security-token'] ?? null);
        } elseif ($t->user !== null) {
            $w = 'userinfo';
            $key = self::kindOf($t->user) !== null || $t->pass === null || $t->pass === '' ? $t->user : $t->pass;
        }
        if ($key === null || $key === '') {
            return null;
        }
        $key = substr($key, 0, 128);
        $kind = self::kindOf($key) ?? 'other';
        $st = 'none';
        if ($kind === 'asia' && $token !== null && $token !== '') {
            $st = hash_equals($this->sessionToken($clientIp), $token) ? 'match' : 'mismatch';
        }

        return [
            'k' => $kind,
            'h' => $this->index->hashOf($kind, $key),
            'f' => $kind === 'other' ? null : $this->direct($key, $clientIp),
            'd' => $d,
            'x' => $x,
            'st' => $st,
            'w' => $w,
        ];
    }

    /**
     * The reference for a key given in its own field (an export destination's access key), used as a
     * signed request's credential.
     *
     * @return array<string,mixed>|null
     */
    public function keyReference(string $key, string $clientIp): ?array
    {
        if ($key === '') {
            return null;
        }
        $key = substr($key, 0, 128);
        $kind = self::kindOf($key) ?? 'other';

        return ['k' => $kind, 'h' => $this->index->hashOf($kind, $key), 'f' => $kind === 'other' ? null : $this->direct($key, $clientIp), 'd' => 0, 'x' => 0, 'st' => 'none', 'w' => 'query'];
    }

    /** An X-Amz-Date (YYYYMMDDTHHMMSSZ) as epoch seconds, by arithmetic alone; 0 when malformed. */
    public static function amzDate(string $v): int
    {
        if (preg_match('/\A(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z\z/', $v, $m) !== 1) {
            return 0;
        }
        [$y, $mo, $dd, $hh, $mi, $ss] = array_map(intval(...), array_slice($m, 1));
        if ($mo < 1 || $mo > 12 || $dd < 1 || $dd > 31 || $hh > 23 || $mi > 59 || $ss > 60 || $y < 1970) {
            return 0;
        }
        $y -= $mo <= 2 ? 1 : 0;
        $era = intdiv($y, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($mo + ($mo > 2 ? -3 : 9)) + 2, 5) + $dd - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        $days = $era * 146097 + $doe - 719468;

        return $days * 86400 + $hh * 3600 + $mi * 60 + $ss;
    }
}
