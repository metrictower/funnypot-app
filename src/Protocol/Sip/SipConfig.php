<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

use Funnypot\App\Render\Fake\Org;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;

/**
 * Configuration for the SIP and RTP VoIP honeypot service.
 */
final class SipConfig
{
    /**
     * Common SIP usernames scanners spray by name (not by number). Kept valid by default so those
     * probes still reach the weak-auth latch instead of being 404'd away as junk.
     * @var list<string>
     */
    private const DEFAULT_EXTENSION_ALLOWLIST = ['admin', 'root', 'sip', 'test', 'operator', 'voip', 'phone'];

    /**
     * Memoized 'org'-mode roster extension set (ext => true) for O(1) membership, so the roster is
     * derived once for the server's lifetime, not rebuilt per probe. null after a build means the
     * roster could not be derived — the caller then falls back to the pattern policy.
     * @var array<string, true>|null
     */
    private ?array $orgExtSet = null;
    private bool $orgExtBuilt = false;

    public function __construct(
        public string $style = 'realistic',
        public string $bind = '0.0.0.0:5060',
        public string $userAgent = 'Asterisk PBX 20.5.0',
        public string $realm = 'asterisk',
        public string $audioMode = 'auto', // 'auto' cycles a discovered persona per caller IP; or force one by folder name, or 'fax'/'ring'
        // Default 'weak': accept only weak/default passwords, like a real misconfigured PBX. Accepting
        // *every* password ('permissive') is itself a tell — no genuine PBX does that.
        public string $authMode = 'weak', // 'weak' (username/default passwords), 'permissive' (any), 'open', 'strict'
        /** @var list<string> */
        public array $defaultPasswords = ['100', '101', '102', '1234', '123456', 'admin', 'password', 'secret', 'pass', 'guest'],
        public bool $recordCalls = true,
        public int $maxActiveCalls = 10,
        public int $perIpCalls = 5,
        public int $maxCallDuration = 300,
        /** End a streaming call after this many seconds with no inbound from the caller (hangup detection). */
        public int $callIdleTimeout = 30,
        // Fixed local RTP media port, published through Docker so inbound caller audio + DTMF reach
        // us. Default 10000 matches the Asterisk PBX persona (its RTP range opens at 10000).
        public int $rtpPort = 10000,
        public float $ringFrequency1 = 440.0,
        public float $ringFrequency2 = 480.0,
        public float $ringCadenceOn = 2.0,
        public float $ringCadenceOff = 4.0,
        public string $audioDir = '',
        public string $recordingsDir = '',
        /** Total on-disk cap for the recordings dir; oldest are pruned past it (disk-exhaustion guard). */
        public int $recordingsMaxBytes = 268435456,
        public string $latchedCredentialsFile = '',
        public bool $latchPasswords = true,
        /**
         * Operator override for the valid-extension policy. null = built-in default (any plausible
         * dialed number + a small username allowlist). A non-empty list of rule strings REPLACES the
         * default: explicit extensions, `*`/`?` globs, or `re:PATTERN` anchored regexes (all matched
         * case-insensitively). See isValidExtension(). Only consulted in 'pattern' mode.
         * @var list<string>|null
         */
        public ?array $validExtensionRules = null,
        /**
         * Which valid-extension policy runs. 'pattern' = the numeric/allowlist (or operator-rule)
         * default; 'org' = the bounded, coherent extension directory of the seeded fake org, so a
         * scanner enumerates exactly the extensions the office HR/directory panels render. See
         * isValidExtension().
         */
        public string $extensionMode = 'pattern',
        /** Persona seed + email domain for 'org' mode, resolved the SAME way the office panels are so
         *  the SIP directory and those panels describe one company. Private per-deploy value. */
        public int $personaSeed = 0,
        public string $personaDomain = '',
        /**
         * Per-source-IP call-admission throttle (adaptive, token-bucket). A flood of INVITE/REGISTER/
         * OPTIONS from one apparent source is silently dropped once its bucket drains — no session, no
         * response bytes (reflection-safe over UDP), and per-call logging collapses to a periodic
         * rollup. $callBurst is how many requests an IP may make before throttling engages (bucket
         * capacity); $callRatePerSec is the sustained refill (0.5 = ~30/min). Set $callBurst <= 0 to
         * disable the throttle entirely. Auto-recovers when the source slows, so a spoofed victim is
         * never permanently blocked.
         */
        public float $callBurst = 30.0,
        public float $callRatePerSec = 0.5,
        /**
         * Credential-crack resistance for the permissive/accept-any auth modes: a real weak PBX does not
         * accept the FIRST password guess (svcrack/rcrack would flag "cracked on attempt #1" as a honeypot
         * tell). Reject the first N guesses per (IP, extension) with 403, then latch + accept — the crack
         * "succeeds" after a believable few tries and the brute-forcer burns more time, while the
         * toll-fraud lure (eventual accept) is preserved. N is seeded per (IP, ext) in [crackMin,crackMax]
         * for a realistic spread. crackMin <= 0 disables it (accept the first guess, the old behaviour).
         */
        public int $crackMin = 2,
        public int $crackMax = 4,
    ) {
        if ($this->audioDir === '') {
            $this->audioDir = dirname(__DIR__, 3) . '/demo/assets/audio';
        }
        if ($this->recordingsDir === '') {
            $this->recordingsDir = dirname(__DIR__, 3) . '/demo/storage/recordings';
        }
        if ($this->latchedCredentialsFile === '') {
            $this->latchedCredentialsFile = dirname(__DIR__, 3) . '/demo/storage/sip-latched.json';
        }
    }

    /**
     * Whether an addressed extension/AOR should be treated as one this PBX hosts. Valid ones get the
     * 401-challenge / call-setup flow; invalid ones get a 404, so an enumeration tool (svwar/svmap)
     * sees a bounded, plausible extension map — a real "fat target" — instead of an impossible
     * PBX that answers every extension. Cosmetic response shaping only; every probe is still logged.
     */
    /**
     * Whether REGISTER/OPTIONS to an unknown AOR is 404-shaped (a bounded, realistic extension map for
     * dictionary scanners). Shapes whenever there is a DEFINITE roster to shape against — 'org' mode,
     * whose validity is the seeded company directory — so a scan sees a real, bounded dialplan (a subset
     * of extensions exist, the rest 404) rather than a PBX that answers every extension, which is the
     * clearest honeypot tell to a human reading sipexten/svwar output. This holds even under the
     * permissive/open auth modes: those still ACCEPT on the roster (and on the by-name allowlist), so the
     * "trivially easy to reach + brute-forceable" lure is preserved on the extensions that DO exist —
     * only off-roster probes are turned away. In 'pattern' mode the validity test is a loose numeric
     * heuristic (any plausible number is "valid"), so shaping there is gated to the credential-guarding
     * modes to avoid 404-ing extensions a real dialplan might plausibly host.
     */
    public function shapesExtensionEnumeration(): bool
    {
        return $this->extensionMode === 'org' || in_array($this->authMode, ['weak', 'strict'], true);
    }

    public function isValidExtension(string $ext): bool
    {
        $ext = trim($ext);
        if ($ext === '') {
            return false;
        }

        // 'org' mode: valid = a member of the seeded roster's bounded extension directory, plus the
        // by-name allowlist so common-name probes are still captured. A scanner therefore maps only
        // the ~90-270 real-looking extensions the office panels show, not an infinite numeric space.
        if ($this->extensionMode === 'org') {
            $set = $this->orgExtensionSet();
            if ($set !== null) {
                return isset($set[$ext])
                    || in_array(strtolower($ext), self::DEFAULT_EXTENSION_ALLOWLIST, true);
            }
            // Roster could not be derived — fall through to the pattern policy so SIP never breaks.
        }

        // 'pattern' mode (also the 'org' fallback): operator-configured policy fully replaces the
        // default when set.
        if ($this->validExtensionRules !== null && $this->validExtensionRules !== []) {
            return $this->matchesRules($ext, $this->validExtensionRules);
        }

        // Default: any plausible dialed number (E.164-ish digits, optional leading '+'). This covers
        // short internal extensions (100, 200) and long toll-fraud target numbers alike.
        if (preg_match('/^\+?[0-9]{1,15}$/', $ext) === 1) {
            return true;
        }

        // Plus a small allowlist of common by-name accounts scanners target.
        return in_array(strtolower($ext), self::DEFAULT_EXTENSION_ALLOWLIST, true);
    }

    /**
     * The seeded org roster's extension directory (sorted), for 'org' mode; an empty list otherwise
     * or when the roster can't be derived. Server-side only — never emitted to a client. Exposed so
     * the coherence between the SIP directory and the office HR/directory panels can be verified.
     * @return list<string>
     */
    public function orgExtensions(): array
    {
        if ($this->extensionMode !== 'org') {
            return [];
        }
        $set = $this->orgExtensionSet();
        if ($set === null) {
            return [];
        }
        // array_keys coerces numeric-string keys ("2002") back to ints, so cast to keep the
        // directory string-typed and byte-identical to the roster's own ext strings.
        $exts = array_map('strval', array_keys($set));
        sort($exts);

        return $exts;
    }

    /**
     * Build (once, memoized) the roster extension set from the same seeded Org the office panels
     * render, so the SIP directory and those panels agree. Fault-isolated: any failure deriving the
     * roster returns null, so the caller degrades to the pattern policy rather than breaking SIP.
     * @return array<string, true>|null
     */
    private function orgExtensionSet(): ?array
    {
        if ($this->orgExtBuilt) {
            return $this->orgExtSet;
        }
        $this->orgExtBuilt = true;

        try {
            $org = Org::fromSeed($this->personaSeed, $this->personaDomain);
            $set = [];
            foreach ($org->people($org->headcount()) as $person) {
                $ext = trim((string) ($person['ext'] ?? ''));
                if ($ext !== '') {
                    $set[$ext] = true;
                }
            }
            // A roster that yields no extensions is treated as a derivation failure (fall back), not
            // an empty directory that would 404 the whole company.
            $this->orgExtSet = $set === [] ? null : $set;
        } catch (\Throwable $e) {
            $this->orgExtSet = null;
        }

        return $this->orgExtSet;
    }

    /**
     * Match an extension against an operator rule list. Each rule is an explicit extension (exact,
     * case-insensitive), a glob using `*`/`?`, or `re:PATTERN` (anchored regex). A bad regex is
     * treated as a non-match rather than throwing — this feeds the fault-isolated listener.
     * @param list<string> $rules
     */
    private function matchesRules(string $ext, array $rules): bool
    {
        $lower = strtolower($ext);
        foreach ($rules as $rule) {
            $rule = trim($rule);
            if ($rule === '') {
                continue;
            }
            if (str_starts_with($rule, 're:')) {
                if (@preg_match('/^' . substr($rule, 3) . '$/i', $ext) === 1) {
                    return true;
                }
                continue;
            }
            if (strpbrk($rule, '*?') !== false) {
                $regex = '/^' . str_replace(['\*', '\?'], ['.*', '.'], preg_quote($rule, '/')) . '$/i';
                if (@preg_match($regex, $ext) === 1) {
                    return true;
                }
                continue;
            }
            if ($lower === strtolower($rule)) {
                return true;
            }
        }

        return false;
    }

    public static function fromEnv(): self
    {
        $style = getenv('FUNNYPOT_SIP_STYLE') ?: (getenv('FUNNYPOT_STYLE') ?: 'realistic');
        $bind = getenv('FUNNYPOT_SIP_BIND') ?: '0.0.0.0:5060';
        $userAgent = getenv('FUNNYPOT_SIP_USER_AGENT') ?: 'Asterisk PBX 20.5.0';
        $realm = getenv('FUNNYPOT_SIP_REALM') ?: 'asterisk';
        $audioMode = strtolower(getenv('FUNNYPOT_SIP_AUDIO_MODE') ?: 'auto');
        $authMode = strtolower(getenv('FUNNYPOT_SIP_AUTH_MODE') ?: 'weak');
        $recordCalls = getenv('FUNNYPOT_SIP_RECORD') !== '0';
        $maxCalls = (int) (getenv('FUNNYPOT_SIP_MAX_CALLS') ?: '10');
        $perIp = (int) (getenv('FUNNYPOT_SIP_PER_IP_CALLS') ?: '5');
        $maxDuration = (int) (getenv('FUNNYPOT_SIP_MAX_DURATION') ?: '300');
        // Call-admission throttle: burst before throttling, sustained refill per second. Empty = default.
        $callBurstRaw = getenv('FUNNYPOT_SIP_CALLS_BURST');
        $callBurst = ($callBurstRaw !== false && $callBurstRaw !== '') ? (float) $callBurstRaw : 30.0;
        $callRateRaw = getenv('FUNNYPOT_SIP_CALLS_PER_SEC');
        $callRate = ($callRateRaw !== false && $callRateRaw !== '') ? (float) $callRateRaw : 0.5;
        // Credential-crack resistance (permissive): reject the first N guesses per (IP,ext) before accept.
        $crackMinRaw = getenv('FUNNYPOT_SIP_CRACK_MIN');
        $crackMin = ($crackMinRaw !== false && $crackMinRaw !== '') ? (int) $crackMinRaw : 2;
        $crackMaxRaw = getenv('FUNNYPOT_SIP_CRACK_MAX');
        $crackMax = ($crackMaxRaw !== false && $crackMaxRaw !== '') ? (int) $crackMaxRaw : 4;
        $idleTimeout = (int) (getenv('FUNNYPOT_SIP_IDLE_TIMEOUT') ?: '30');
        $rtpPort = (int) (getenv('FUNNYPOT_SIP_RTP_PORT') ?: '10000');
        $audioDir = getenv('FUNNYPOT_SIP_AUDIO_DIR') ?: '';
        $recordingsDir = getenv('FUNNYPOT_SIP_RECORDINGS_DIR') ?: '';
        $recMaxBytes = (int) (getenv('FUNNYPOT_SIP_REC_MAX_BYTES') ?: '268435456');
        $latchedFile = getenv('FUNNYPOT_SIP_LATCHED_FILE') ?: '';
        $latchPasswords = getenv('FUNNYPOT_SIP_LATCH_PASSWORDS') !== '0';

        // Comma-separated valid-extension policy: explicit extensions, globs, or `re:PATTERN`
        // regexes. Empty/unset keeps the built-in default (see SipConfig::isValidExtension()).
        $validExtRaw = getenv('FUNNYPOT_SIP_VALID_EXTENSIONS');
        $validExtRules = null;
        if ($validExtRaw !== false && trim($validExtRaw) !== '') {
            $validExtRules = array_values(array_filter(
                array_map('trim', explode(',', $validExtRaw)),
                static fn (string $s): bool => $s !== ''
            ));
            if ($validExtRules === []) {
                $validExtRules = null;
            }
        }

        // Extension policy mode. 'org' binds the valid set to the seeded company roster; anything
        // else keeps the 'pattern' (numeric/allowlist) default.
        $extensionMode = strtolower(getenv('FUNNYPOT_SIP_EXTENSION_MODE') ?: 'pattern');
        if ($extensionMode !== 'org') {
            $extensionMode = 'pattern';
        }

        // Resolve the persona seed (and, for 'org' mode, its email domain) exactly as the office
        // panels do — from the private per-deploy material — so the SIP extension directory and the
        // HR/directory panels present one coherent company. Fault-isolated: if the identity can't be
        // derived, seed/domain stay at their defaults and 'org' mode degrades to the pattern policy.
        $personaMaterial = getenv('FUNNYPOT_PERSONA_SEED') ?: (getenv('FUNNYPOT_PERSONA_SECRET') ?: 'funnypot');
        $personaSeed = 0;
        $personaDomain = '';
        try {
            $personaSeed = PersonaIdentity::seedFromMaterial($personaMaterial);
            if ($extensionMode === 'org') {
                $personaDomain = VisualPersona::fromSeed($personaSeed)->domain();
            }
        } catch (\Throwable $e) {
            $personaSeed = 0;
            $personaDomain = '';
        }

        return new self(
            style: $style,
            bind: $bind,
            userAgent: $userAgent,
            realm: $realm,
            audioMode: $audioMode,
            authMode: $authMode,
            recordCalls: $recordCalls,
            maxActiveCalls: max(1, $maxCalls),
            perIpCalls: max(1, $perIp),
            maxCallDuration: max(10, $maxDuration),
            callIdleTimeout: max(5, $idleTimeout),
            rtpPort: ($rtpPort > 0 && $rtpPort < 65536) ? $rtpPort : 10000,
            audioDir: $audioDir,
            recordingsDir: $recordingsDir,
            recordingsMaxBytes: max(0, $recMaxBytes),
            latchedCredentialsFile: $latchedFile,
            latchPasswords: $latchPasswords,
            validExtensionRules: $validExtRules,
            extensionMode: $extensionMode,
            personaSeed: $personaSeed,
            personaDomain: $personaDomain,
            callBurst: max(0.0, $callBurst),
            callRatePerSec: max(0.0, $callRate),
            crackMin: $crackMin,
            crackMax: max($crackMin, $crackMax),
        );
    }
}
