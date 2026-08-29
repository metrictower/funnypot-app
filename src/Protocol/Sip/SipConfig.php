<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

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
         * case-insensitively). See isValidExtension().
         * @var list<string>|null
         */
        public ?array $validExtensionRules = null,
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
    public function isValidExtension(string $ext): bool
    {
        $ext = trim($ext);
        if ($ext === '') {
            return false;
        }

        // Operator-configured policy fully replaces the default when set.
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
        );
    }
}
