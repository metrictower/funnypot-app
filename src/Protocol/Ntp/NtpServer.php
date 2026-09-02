<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ntp;

/**
 * Zero-dependency, single-process UDP server for the low-interaction NTP honeypot (port 123).
 * Parses the 48-byte NTP packet in pure PHP on a non-blocking stream_select loop over one UDP socket
 * to fingerprint scanners and, above all, to detect amplification/reflection abuse.
 *
 * Deliberately inert: it runs no real clock discipline and serves no management data. A normal client
 * request (mode 3) is answered with a plausible mode-4 server reply. The reply's timestamps read NO
 * wall clock — they are derived from the client's own transmit timestamp (echoed into originate) plus
 * a fixed seeded base — so the honeypot needs neither a real clock nor a time() call to look current.
 *
 * ANTI-AMPLIFICATION is the whole point of an NTP honeypot:
 * 1. Mode 6 (control) and mode 7 (private, incl. the CVE-2013-5211 MONLIST / REQ_MON_GETLIST) are the
 *    classic reflection/DDoS vectors — a tiny request pulls a huge multi-packet reply on real servers.
 *    Here they are NEVER answered: the probe is logged at high severity and dropped, so the box can
 *    never be turned into an amplifier.
 * 2. No emitted datagram is ever larger than the request that triggered it (amplification factor <= 1).
 * On top of that, replies are metered per source IP with a token bucket (a spoofed request forges its
 * source as a victim, so every reply we emit lands on that victim).
 *
 * Captured intel: the client version and mode, the transmit timestamp it offered, and — for the abuse
 * vectors — the mode-6 opcode / mode-7 request code (e.g. monlist).
 */
final class NtpServer
{
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const READ_CHUNK = 65535;        // a single UDP datagram
    private const INBUF_CAP = 65535;         // an NTP message never legitimately approaches this
    private const MAX_DGRAMS_PER_TICK = 64;  // bound the drain so a flood can't spin one tick forever

    public const NTP_PACKET_SIZE = 48;       // the fixed NTP header a mode 3/4 packet always carries

    // NTP modes carried in the low 3 bits of the leading byte.
    public const MODE_RESERVED = 0;
    public const MODE_SYM_ACTIVE = 1;
    public const MODE_SYM_PASSIVE = 2;
    public const MODE_CLIENT = 3;
    public const MODE_SERVER = 4;
    public const MODE_BROADCAST = 5;
    public const MODE_CONTROL = 6;   // reflection vector
    public const MODE_PRIVATE = 7;   // reflection vector (monlist)

    // Small, deterministic service delays added to the reply timestamps, in NTP fraction units
    // (1 second == 2^32). These make receive/transmit trail originate by a believable few microseconds.
    private const RX_DELTA_FRAC = 0x00010000; // ~15 microseconds
    private const TX_DELTA_FRAC = 0x00008000; // ~7.5 microseconds

    /**
     * Per-source-IP token bucket throttling UDP responses (anti-reflection). A spoofed request forges
     * its source as a victim, so every reply we emit lands on that victim — capping replies per
     * apparent source bounds how hard the honeypot can be turned into a reflector.
     * @var array<string, array{tokens: float, last: float}>
     */
    private array $udpResponseBuckets = [];
    private const UDP_RESP_BURST = 20.0;      // bucket capacity
    private const UDP_RESP_RATE = 10.0;       // tokens refilled per second
    private const UDP_BUCKET_MAX_IPS = 4096;  // cap tracked IPs so the map can't grow unbounded

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private NtpConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:123").
     */
    public function run(string $bind): void
    {
        $sock = @stream_socket_server("udp://{$bind}", $errno, $errstr, STREAM_SERVER_BIND);
        if ($sock === false) {
            fwrite(STDERR, "funnypot-ntp: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($sock, false);
        fwrite(STDERR, "funnypot-ntp (stratum {$this->config->stratum}) listening on {$bind} (UDP)\n");

        $id = 0;

        while (true) {
            $read = [$sock];
            $write = null;
            $except = null;

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }

            // Drain the readable socket in a bounded loop: a UDP socket signals readable once but may
            // hold several queued datagrams.
            for ($i = 0; $i < self::MAX_DGRAMS_PER_TICK; $i++) {
                $peer = '';
                $data = @stream_socket_recvfrom($sock, self::READ_CHUNK, 0, $peer);
                if ($data === false || $data === '' || $peer === '') {
                    break;
                }

                [$ip, $clientPort] = self::splitAddr((string) $peer);
                $session = new NtpSession($ip, $clientPort, ++$id);
                $session->inbuf = $data;

                // Fault isolation: a malformed datagram must degrade (log + skip) — never escape the
                // loop and crash the listener.
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($ip, $e);
                    continue;
                }

                if ($session->outbuf === '') {
                    continue;
                }

                // Anti-reflection throttle: a spoofed source drains its bucket and its reply is dropped
                // rather than reflected at the forged victim.
                if (!$this->udpResponseAllowed($ip)) {
                    continue;
                }

                @stream_socket_sendto($sock, $session->outbuf, 0, (string) $peer);
            }
        }
    }

    /**
     * Parses the datagram held in $s->inbuf, captures intel, logs the event, and queues a size-capped
     * response in $s->outbuf when (and only when) the request is a normal client query. Safe to drive
     * directly with raw bytes in tests.
     */
    public function processInbound(NtpSession $s): void
    {
        $data = $s->inbuf;
        $s->inbuf = '';
        if ($data === '') {
            return;
        }
        if (strlen($data) > self::INBUF_CAP) {
            $this->logUnknown($s, sprintf('oversize datagram (%d bytes)', strlen($data)));

            return;
        }

        $pkt = self::parsePacket($data);
        if ($pkt === null) {
            $this->logUnknown($s, 'unparseable NTP packet');

            return;
        }

        $s->version = $pkt['vn'];
        $s->mode = $pkt['mode'];
        $mode = $pkt['mode'];

        // Mode 6 (control) and mode 7 (private / monlist) are the reflection vectors: never answer,
        // never with even a size-safe echo of our own accord here — record the abuse and drop.
        if ($mode === self::MODE_CONTROL || $mode === self::MODE_PRIVATE) {
            $this->logMonlistProbe($s, $data);

            return;
        }

        if ($mode === self::MODE_CLIENT) {
            if (strlen($data) < self::NTP_PACKET_SIZE) {
                $this->logUnknown($s, sprintf('short client packet (%d bytes)', strlen($data)));

                return;
            }
            $this->logClient($s, $pkt);

            $response = self::buildClientResponse($pkt, $this->config);

            // ANTI-AMPLIFICATION: never emit a datagram larger than the one received. Our reply is a
            // fixed 48 bytes and a valid client request is at least that, so this only ever guards the
            // edge; when it would exceed, drop rather than reflect.
            if (strlen($response) > strlen($data)) {
                $response = '';
            }
            $s->outbuf = $response;

            return;
        }

        // Modes 0/1/2/4/5 (reserved, symmetric, server reply, broadcast) are not a client query we
        // model: record the probe, never reply.
        $this->logUnknown($s, sprintf('unmodelled mode %d (%s)', $mode, self::describeMode($mode)));
    }

    // ---- Parsing ------------------------------------------------------------------------------

    /**
     * Parses an NTP packet's leading byte (always present) and, when the full 48-byte header is
     * present, the fields the honeypot reads. Returns null only on an empty buffer.
     *
     * @return array{li:int,vn:int,mode:int,stratum:int,poll:int,precision:int,txSeconds:int,txFraction:int,full:bool}|null
     */
    public static function parsePacket(string $data): ?array
    {
        if ($data === '') {
            return null;
        }

        $b0 = ord($data[0]);
        $li = ($b0 >> 6) & 0x03;
        $vn = ($b0 >> 3) & 0x07;
        $mode = $b0 & 0x07;

        $full = strlen($data) >= self::NTP_PACKET_SIZE;

        return [
            'li' => $li,
            'vn' => $vn,
            'mode' => $mode,
            'stratum' => $full ? ord($data[1]) : 0,
            'poll' => $full ? self::signed8(ord($data[2])) : 0,
            'precision' => $full ? self::signed8(ord($data[3])) : 0,
            // Transmit timestamp (t3) lives at bytes 40-47: seconds then fraction, big-endian.
            'txSeconds' => $full ? self::be32($data, 40) : 0,
            'txFraction' => $full ? self::be32($data, 44) : 0,
            'full' => $full,
        ];
    }

    // ---- Response building --------------------------------------------------------------------

    /**
     * Builds the 48-byte mode-4 server response for a parsed mode-3 client request. Timestamps are
     * derived deterministically: the client's transmit timestamp (t3) is echoed into originate (t1),
     * receive and transmit trail it by a fixed few microseconds, and the reference timestamp sits a
     * plausible interval earlier. When the client sent no usable timestamp the fixed seeded base is
     * used instead. No wall clock is ever read, so the same request always yields the same bytes.
     *
     * @param array{li:int,vn:int,mode:int,stratum:int,poll:int,precision:int,txSeconds:int,txFraction:int,full:bool} $req
     */
    public static function buildClientResponse(array $req, NtpConfig $config): string
    {
        $vn = $req['vn'];
        // LI = 0 (no warning), VN echoed, Mode = 4 (server).
        $b0 = (0 << 6) | (($vn & 0x07) << 3) | self::MODE_SERVER;

        $stratum = $config->stratum & 0xFF;
        // Echo the client's poll when it is in a sane range, else the persona default.
        $poll = ($req['poll'] >= 4 && $req['poll'] <= 17) ? $req['poll'] : $config->poll;
        $precision = $config->precision & 0xFF;

        // Anchor the reply to the client's own clock: its transmit timestamp becomes our originate.
        $originSecs = $req['txSeconds'];
        $originFrac = $req['txFraction'];
        if ($originSecs === 0 && $originFrac === 0) {
            // No usable client time: fall back to the fixed, deterministic base.
            $originSecs = $config->baseNtpSeconds & 0xFFFFFFFF;
            $originFrac = 0;
        }

        [$rxSecs, $rxFrac] = self::addFraction($originSecs, $originFrac, self::RX_DELTA_FRAC);
        [$txSecs, $txFrac] = self::addFraction($rxSecs, $rxFrac, self::TX_DELTA_FRAC);

        // Reference timestamp: when the clock last synced, a plausible interval before "now".
        $refSecs = ($originSecs >= $config->referenceAgeSeconds)
            ? ($originSecs - $config->referenceAgeSeconds)
            : $originSecs;

        return chr($b0)
            . chr($stratum)
            . chr($poll & 0xFF)
            . chr($precision)
            . self::packShort($config->rootDelaySeconds)
            . self::packShort($config->rootDispersionSeconds)
            . self::encodeRefid($config->refid, $stratum)
            . self::packTimestamp($refSecs, 0)
            . self::packTimestamp($originSecs, $originFrac)
            . self::packTimestamp($rxSecs, $rxFrac)
            . self::packTimestamp($txSecs, $txFrac);
    }

    /**
     * Encodes a 4-byte NTP reference identifier. For stratum >= 2 an IPv4 address is packed as its 4
     * network bytes (the upstream server it syncs to); otherwise an ASCII clock-source code is taken
     * verbatim, null-padded/truncated to 4 bytes.
     */
    public static function encodeRefid(string $refid, int $stratum): string
    {
        if ($stratum >= 2 && substr_count($refid, '.') === 3) {
            $packed = @inet_pton($refid);
            if ($packed !== false && strlen($packed) === 4) {
                return $packed;
            }
        }

        return substr(str_pad($refid, 4, "\x00"), 0, 4);
    }

    /** Encodes seconds as an NTP short format value (16.16 unsigned fixed point), 4 bytes. */
    private static function packShort(float $seconds): string
    {
        $v = (int) round($seconds * 65536.0);
        if ($v < 0) {
            $v = 0;
        }

        return pack('N', $v & 0xFFFFFFFF);
    }

    /** Encodes a 64-bit NTP timestamp: 32-bit seconds then 32-bit fraction, big-endian. */
    private static function packTimestamp(int $secs, int $frac): string
    {
        return pack('N', $secs & 0xFFFFFFFF) . pack('N', $frac & 0xFFFFFFFF);
    }

    /**
     * Adds a fraction delta to a (seconds, fraction) pair, carrying into seconds and keeping both in
     * the 32-bit unsigned range. Seconds and fraction are handled separately because the full 64-bit
     * NTP value can exceed PHP's signed integer range.
     *
     * @return array{0:int,1:int}
     */
    private static function addFraction(int $secs, int $frac, int $addFrac): array
    {
        $frac += $addFrac;
        $secs += intdiv($frac, 0x100000000);
        $frac %= 0x100000000;

        return [$secs & 0xFFFFFFFF, $frac & 0xFFFFFFFF];
    }

    private static function be32(string $b, int $off): int
    {
        return (ord($b[$off]) << 24)
            | (ord($b[$off + 1]) << 16)
            | (ord($b[$off + 2]) << 8)
            | ord($b[$off + 3]);
    }

    private static function signed8(int $b): int
    {
        return $b >= 128 ? $b - 256 : $b;
    }

    // ---- Anti-reflection throttle -------------------------------------------------------------

    /**
     * Token-bucket admission for a UDP reply to $ip. Returns false when the apparent source has
     * drained its bucket, so the reply is dropped rather than reflected.
     */
    private function udpResponseAllowed(string $ip): bool
    {
        $now = microtime(true);

        if (!isset($this->udpResponseBuckets[$ip])) {
            // Bound the map: when full, drop the least-recently-refilled entry before adding one.
            if (count($this->udpResponseBuckets) >= self::UDP_BUCKET_MAX_IPS) {
                $oldestKey = null;
                $oldestAt = INF;
                foreach ($this->udpResponseBuckets as $k => $b) {
                    if ($b['last'] < $oldestAt) {
                        $oldestAt = $b['last'];
                        $oldestKey = $k;
                    }
                }
                if ($oldestKey !== null) {
                    unset($this->udpResponseBuckets[$oldestKey]);
                }
            }
            $this->udpResponseBuckets[$ip] = ['tokens' => self::UDP_RESP_BURST, 'last' => $now];
        }

        $bucket = &$this->udpResponseBuckets[$ip];
        $elapsed = max(0.0, $now - $bucket['last']);
        $bucket['tokens'] = min(self::UDP_RESP_BURST, $bucket['tokens'] + $elapsed * self::UDP_RESP_RATE);
        $bucket['last'] = $now;

        if ($bucket['tokens'] < 1.0) {
            return false;
        }
        $bucket['tokens'] -= 1.0;

        return true;
    }

    // ---- Logging ------------------------------------------------------------------------------

    /**
     * @param array{li:int,vn:int,mode:int,stratum:int,poll:int,precision:int,txSeconds:int,txFraction:int,full:bool} $pkt
     */
    private function logClient(NtpSession $s, array $pkt): void
    {
        $this->logEvent([
            'event' => 'ntp_client',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'low',
            'path' => sprintf(
                'NTP client request v%d mode=3 poll=%d tx=%08x.%08x',
                $pkt['vn'],
                $pkt['poll'],
                $pkt['txSeconds'],
                $pkt['txFraction']
            ),
        ]);
    }

    /**
     * Records a mode-6 (control) or mode-7 (private / monlist) request as an amplification-abuse probe
     * at high severity. These are never answered; the log is the intel.
     */
    private function logMonlistProbe(NtpSession $s, string $data): void
    {
        $mode = $s->mode ?? 0;
        if ($mode === self::MODE_PRIVATE) {
            // Mode 7 header: flags(1), auth/seq(1), implementation(1), request code(1).
            $impl = strlen($data) >= 3 ? ord($data[2]) : 0;
            $reqCode = strlen($data) >= 4 ? ord($data[3]) : 0;
            $detail = sprintf(
                'NTP mode 7 (private) impl=%d reqcode=%d%s',
                $impl,
                $reqCode,
                self::isMonlistReqCode($reqCode) ? ' MONLIST/REQ_MON_GETLIST' : ''
            );
        } else {
            // Mode 6 header: flags(1), op(1) — the response bit + opcode in the low 5 bits.
            $op = strlen($data) >= 2 ? (ord($data[1]) & 0x1F) : 0;
            $detail = sprintf('NTP mode 6 (control) opcode=%d', $op);
        }

        $this->logEvent([
            'event' => 'ntp_monlist_probe',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'high',
            'path' => 'NTP amplification probe: ' . $detail . ' (dropped, never reflected)',
        ]);
    }

    private function logUnknown(NtpSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'ntp_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'low',
            'path' => 'NTP unmodelled input: ' . $detail,
        ]);
    }

    /** True for the request codes the CVE-2013-5211 monlist reflection abused. */
    private static function isMonlistReqCode(int $reqCode): bool
    {
        // REQ_MON_GETLIST (42) and REQ_MON_GETLIST_1 (0) are the two monlist variants.
        return $reqCode === 42 || $reqCode === 0;
    }

    private static function describeMode(int $mode): string
    {
        return match ($mode) {
            self::MODE_RESERVED => 'reserved',
            self::MODE_SYM_ACTIVE => 'symmetric active',
            self::MODE_SYM_PASSIVE => 'symmetric passive',
            self::MODE_CLIENT => 'client',
            self::MODE_SERVER => 'server',
            self::MODE_BROADCAST => 'broadcast',
            self::MODE_CONTROL => 'control',
            self::MODE_PRIVATE => 'private',
            default => 'unknown',
        };
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'NTP';
        $entry['proto'] = 'ntp';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        // FP-0247 (Fix A): single-datagram UDP is spoofable — fail-closed. Only a verified round-trip
        // may upgrade this (see SipServer's $validRoundTrip). `??=` so a future per-event upgrade wins.
        $entry['reportable'] ??= false;
        ($this->logger)($entry);
    }

    /** Records a per-datagram fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => 123,
                'path' => 'NTP internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function splitAddr(string $addr): array
    {
        $lastColon = strrpos($addr, ':');
        if ($lastColon !== false) {
            return [substr($addr, 0, $lastColon), (int) substr($addr, $lastColon + 1)];
        }

        return [$addr, 123];
    }
}
