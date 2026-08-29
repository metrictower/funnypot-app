<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Configuration for the SIP and RTP VoIP honeypot service.
 */
final class SipConfig
{
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
        );
    }
}
