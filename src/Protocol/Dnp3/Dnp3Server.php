<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dnp3;

/**
 * Zero-dependency, single-process TCP server for the low-interaction DNP3 honeypot (port 20000).
 * Speaks just enough of the DNP3 (IEEE 1815) data-link, transport and application layers in pure PHP,
 * on a non-blocking stream_select event loop, to answer the handshake a SCADA scanner performs and to
 * log the outstation enumeration it runs.
 *
 * Wire framing: every data-link frame is start bytes 0x05 0x64, a 1-octet length, a control octet,
 * a 2-octet destination and 2-octet source address (little-endian), and a 2-octet CRC over those
 * eight header bytes. The length counts control + addresses + user data (never the CRCs). Any user
 * data (transport byte + application fragment) then follows in blocks of up to 16 octets, each with
 * its own 2-octet CRC. Both CRCs use CRC-16/DNP.
 *
 * Deliberately inert. The honeypot models three recon surfaces and nothing else:
 * - Link functions (reset / test / request-link-status): answered with a link ACK or LINK_STATUS so
 *   the scanner's handshake completes.
 * - Application READ (function 0x01), including class-0/1/2/3 object requests: the requested object
 *   groups are captured (point-map recon) and answered with a tiny block of fabricated, always-off
 *   binary inputs plus Internal Indications — never real point data.
 * - Any other application function (WRITE, SELECT, OPERATE, restarts, ...): captured and refused with
 *   a "function not implemented" response. No control is ever actuated and no state ever changes.
 */
final class Dnp3Server
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms
    private const INBUF_CAP = 65536; // a DNP3 frame is at most ~292 bytes; guard against buffer exhaustion

    private const DEFAULT_PORT = 20000;

    // Data-link frame start octets (0x0564).
    private const START1 = 0x05;
    private const START2 = 0x64;

    // Data-link function codes (control octet, low nibble). PRM=1 primary (master-sourced).
    private const LINK_RESET_LINK_STATES = 0x0;
    private const LINK_RESET_USER_PROCESS = 0x1;
    private const LINK_TEST_LINK_STATES = 0x2;
    private const LINK_CONFIRMED_USER_DATA = 0x3;
    private const LINK_UNCONFIRMED_USER_DATA = 0x4;
    private const LINK_REQUEST_LINK_STATUS = 0x9;

    // Data-link function codes for secondary (PRM=0, outstation-sourced) frames we emit.
    private const LINK_ACK = 0x0;
    private const LINK_STATUS = 0xB;

    // Application function codes.
    private const APP_CONFIRM = 0x00;
    private const APP_READ = 0x01;
    private const APP_RESPONSE = 0x81;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private Dnp3Config $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:20000").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-dnp3: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-dnp3 (outstation {$this->config->outstationAddress}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:Dnp3Session,ip:string}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['session']->outbuf !== '') {
                    $write[] = $c['sock'];
                }
            }
            $except = [];

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }

            $now = time();

            foreach ($read as $r) {
                if ($r === $server) {
                    $this->accept($server, $conns, $perIp, $port, $now);
                    continue;
                }

                $id = get_resource_id($r);
                if (!isset($conns[$id])) {
                    continue;
                }

                $session = $conns[$id]['session'];
                $data = @fread($r, self::READ_CHUNK);

                if ($data === false || ($data === '' && feof($r))) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($data === '') {
                    continue;
                }

                $session->lastActiveTime = $now;
                $session->inbuf .= $data;

                // Guard against inbound buffer exhaustion — the exchange is tiny.
                if (strlen($session->inbuf) > self::INBUF_CAP) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Fault isolation: a malformed packet must close only this connection, never escape
                // the loop and crash the listener (degrade, never crash).
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'] ?? '', $e);
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($session->close) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
            }

            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (!isset($conns[$id])) {
                    continue;
                }
                $session = $conns[$id]['session'];
                if ($session->outbuf === '') {
                    continue;
                }

                $written = @fwrite($w, $session->outbuf);
                if ($written === false) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                $session->outbuf = substr($session->outbuf, $written);
            }

            foreach ($conns as $id => $c) {
                if ($now - $c['session']->lastActiveTime > self::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0);
        if ($sock === false) {
            return;
        }
        stream_set_blocking($sock, false);

        $name = (string) @stream_socket_get_name($sock, true);
        $ip = ($colon = strrpos($name, ':')) !== false ? substr($name, 0, $colon) : $name;
        $clientPort = ($colon !== false) ? (int) substr($name, $colon + 1) : 0;

        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }

        $id = get_resource_id($sock);
        $session = new Dnp3Session($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "DNP3 connection from {$ip}:{$clientPort}",
        ]);
    }

    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $ip = $conns[$id]['ip'];
        @fclose($conns[$id]['sock']);
        unset($conns[$id]);

        if (isset($perIp[$ip])) {
            $perIp[$ip]--;
            if ($perIp[$ip] <= 0) {
                unset($perIp[$ip]);
            }
        }
    }

    /**
     * Frames the inbound stream into DNP3 data-link frames and dispatches each one. Safe to drive
     * directly with raw bytes in tests.
     */
    public function processInbound(Dnp3Session $s): void
    {
        while (true) {
            if (strlen($s->inbuf) < 10) {
                return; // need the full 8-byte header + its 2-byte CRC first
            }
            if (ord($s->inbuf[0]) !== self::START1 || ord($s->inbuf[1]) !== self::START2) {
                // Not a DNP3 frame (a TLS ClientHello, HTTP, or junk). Nothing to model — record and drop.
                $this->logUnknown($s, sprintf('non-DNP3 start bytes 0x%02X 0x%02X', ord($s->inbuf[0]), ord($s->inbuf[1])));
                $s->close = true;

                return;
            }

            $length = ord($s->inbuf[2]);
            if ($length < 5) {
                // Length counts control + both addresses (5) plus user data, so it is never below 5.
                $this->logUnknown($s, "bad link length {$length}");
                $s->close = true;

                return;
            }

            $userDataLen = $length - 5;
            $total = self::frameLength($userDataLen);
            if ($total > self::INBUF_CAP) {
                $this->logUnknown($s, 'frame exceeds cap');
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < $total) {
                return; // wait for the rest of this frame
            }

            $frame = substr($s->inbuf, 0, $total);
            $s->inbuf = substr($s->inbuf, $total);

            $this->handleFrame($s, $frame, $userDataLen);
            if ($s->close) {
                return;
            }
        }
    }

    private function handleFrame(Dnp3Session $s, string $frame, int $userDataLen): void
    {
        $link = self::parseLinkHeader($frame);
        if ($link === null) {
            $this->logUnknown($s, 'unparseable link header');

            return;
        }
        $s->sourceAddress = $link['source'];
        $s->destAddress = $link['dest'];
        $s->lastLinkFunction = $link['function'];

        // Secondary (PRM=0) frames are responses, not requests: a master never sends them to us.
        // Record the anomaly, never reply (replying to a non-request is a tell and useless).
        if ($link['prm'] === 0) {
            $this->logLink($s, $link, 'low');

            return;
        }

        switch ($link['function']) {
            case self::LINK_RESET_LINK_STATES:
            case self::LINK_RESET_USER_PROCESS:
            case self::LINK_TEST_LINK_STATES:
                $this->logLink($s, $link, 'low');
                $s->outbuf .= $this->buildLinkControlResponse(self::LINK_ACK, $link['source']);
                break;

            case self::LINK_REQUEST_LINK_STATUS:
                $this->logLink($s, $link, 'low');
                $s->outbuf .= $this->buildLinkControlResponse(self::LINK_STATUS, $link['source']);
                break;

            case self::LINK_CONFIRMED_USER_DATA:
            case self::LINK_UNCONFIRMED_USER_DATA:
                $userData = self::stripBlockCrcs($frame, $userDataLen);
                if ($userData === null) {
                    $this->logUnknown($s, 'truncated user-data blocks');

                    return;
                }
                $this->handleApplication($s, $userData, $link);
                break;

            default:
                // An unmodelled link function is recon in itself; record it and keep the connection
                // open so the attacker's later, modelled frames are still captured.
                $this->logUnknown($s, sprintf('unsupported link function 0x%X', $link['function']));
        }
    }

    /**
     * Dispatches the application fragment carried in a user-data frame: an application READ is
     * captured and answered with fabricated data; any other function is captured and refused.
     *
     * @param array{source:int,dest:int,...} $link
     */
    private function handleApplication(Dnp3Session $s, string $userData, array $link): void
    {
        $app = self::parseApplication($userData);
        if ($app === null) {
            $this->logUnknown($s, 'malformed application fragment');

            return;
        }
        $s->lastAppFunction = $app['function'];
        $s->appSeq = $app['seq'];
        $func = $app['function'];

        if ($func === self::APP_READ) {
            $objects = self::parseObjectHeaders($app['objects'], true);
            $s->readObjects = $objects;

            $this->logEvent([
                'event' => 'dnp3_read',
                'ip' => $s->ip,
                'port' => $s->port,
                'severity' => 'medium',
                'path' => sprintf(
                    'DNP3 READ src=%d dest=%d objects=[%s]',
                    $link['source'],
                    $link['dest'],
                    self::describeObjects($objects)
                ),
                'src_addr' => $link['source'],
                'dest_addr' => $link['dest'],
                'app_function' => 'READ',
                'objects' => self::describeObjects($objects),
            ]);

            $s->outbuf .= $this->buildReadResponse($s);

            return;
        }

        // Any non-read function: capture it (its object header is the target of a control command) and,
        // for a CONFIRM, stay silent; for everything else, refuse it — inert, never actuated.
        $objects = self::parseObjectHeaders($app['objects'], false);
        $s->readObjects = $objects;
        $severity = self::appSeverity($func);
        $note = in_array($severity, ['critical', 'high'], true) ? ' (inert, not actuated)' : '';

        $this->logEvent([
            'event' => 'dnp3_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $severity,
            'path' => sprintf(
                'DNP3 %s%s src=%d dest=%d objects=[%s]',
                self::appFunctionName($func),
                $note,
                $link['source'],
                $link['dest'],
                self::describeObjects($objects)
            ),
            'src_addr' => $link['source'],
            'dest_addr' => $link['dest'],
            'app_function' => self::appFunctionName($func),
        ]);

        // A CONFIRM acknowledges our own response; nothing to answer. Everything else gets a refusal.
        if ($func !== self::APP_CONFIRM) {
            $s->outbuf .= $this->buildRefusalResponse($s);
        }
    }

    // ---- Response building ---------------------------------------------------------------------

    /**
     * A secondary (PRM=0) link-layer control frame: an ACK or a LINK_STATUS, carrying no user data, so
     * a scanner's reset / request-link-status handshake completes against a live-looking outstation.
     */
    private function buildLinkControlResponse(int $func, int $masterAddress): string
    {
        // DIR=0 (outstation-sourced), PRM=0 (secondary); no FCB/DFC. Control octet is just the function.
        $control = $func & 0x0F;

        return self::assembleFrame($control, $masterAddress, $this->config->outstationAddress, '');
    }

    /**
     * Application READ response: FIR|FIN, function RESPONSE(0x81), Internal Indications, then a tiny
     * block of fabricated Binary Input points. The points are all-off with only the ONLINE flag set —
     * synthetic, never real process data.
     */
    private function buildReadResponse(Dnp3Session $s): string
    {
        $ac = 0xC0 | ($s->appSeq & 0x0F); // FIR|FIN, sequence echoed
        $payload = chr($ac) . chr(self::APP_RESPONSE) . $this->iin($s, false) . $this->staticBinaryBlock();

        return $this->buildDataFrame($s, $payload);
    }

    /**
     * Application response refusing an unmodelled function: FIR|FIN, RESPONSE(0x81), and IIN with the
     * "function not implemented" bit set, so a control command is answered plausibly but never obeyed.
     */
    private function buildRefusalResponse(Dnp3Session $s): string
    {
        $ac = 0xC0 | ($s->appSeq & 0x0F);
        $payload = chr($ac) . chr(self::APP_RESPONSE) . $this->iin($s, true);

        return $this->buildDataFrame($s, $payload);
    }

    /**
     * Wraps an application payload in a transport header and a primary (PRM=1) UNCONFIRMED_USER_DATA
     * data-link frame addressed back to the master, with our outstation address as the source.
     */
    private function buildDataFrame(Dnp3Session $s, string $payload): string
    {
        // Transport header: FIR|FIN (single, unsegmented) with our own advancing sequence.
        $transport = 0xC0 | ($s->outstationTransportSeq & 0x3F);
        $s->outstationTransportSeq = ($s->outstationTransportSeq + 1) & 0x3F;
        $userData = chr($transport) . $payload;

        // Control octet: DIR=0, PRM=1, function UNCONFIRMED_USER_DATA(0x4) => 0x44.
        $control = 0x40 | self::LINK_UNCONFIRMED_USER_DATA;

        return self::assembleFrame($control, $s->sourceAddress ?? 0, $this->config->outstationAddress, $userData);
    }

    /**
     * The two Internal Indications octets. IIN1.7 (device restart) is set on the first response of the
     * session when configured, mirroring a freshly booted RTU; IIN2.0 marks an unsupported function.
     */
    private function iin(Dnp3Session $s, bool $functionNotImplemented): string
    {
        $iin1 = 0x00;
        if ($this->config->indicateRestart && !$s->restartReported) {
            $iin1 |= 0x80; // device restart
            $s->restartReported = true;
        }
        $iin2 = 0x00;
        if ($functionNotImplemented) {
            $iin2 |= 0x01; // function code not implemented
        }

        return chr($iin1) . chr($iin2);
    }

    /**
     * A Binary Input (group 1) variation 2 (with flags) block covering points 0..n-1, each octet the
     * ONLINE flag with state 0. Fabricated and static — never a real point value.
     */
    private function staticBinaryBlock(): string
    {
        $count = $this->config->staticBinaryPoints;
        if ($count <= 0) {
            return '';
        }
        // group(1)=1, variation(1)=2, qualifier(1)=0x00 (8-bit start/stop), start(1)=0, stop(1)=n-1.
        $header = chr(0x01) . chr(0x02) . chr(0x00) . chr(0x00) . chr(($count - 1) & 0xFF);
        $points = str_repeat(chr(0x01), $count); // ONLINE flag set, state 0

        return $header . $points;
    }

    /**
     * Assembles a complete DNP3 data-link frame: the 8-byte header and its CRC, then the user data
     * split into 16-octet blocks each with its own CRC. Shared by every reply and by the tests.
     */
    public static function assembleFrame(int $control, int $dest, int $source, string $userData): string
    {
        $length = 5 + strlen($userData);
        $header = chr(self::START1) . chr(self::START2) . chr($length & 0xFF) . chr($control & 0xFF)
            . chr($dest & 0xFF) . chr(($dest >> 8) & 0xFF)
            . chr($source & 0xFF) . chr(($source >> 8) & 0xFF);
        $header .= self::crcBytesLe($header);

        return $header . self::addBlockCrcs($userData);
    }

    // ---- Parsing (pure, test-drivable) ---------------------------------------------------------

    /**
     * Bytes on the wire for a frame whose user-data (transport + application) length is $userDataLen:
     * the 10-byte header block plus the user data plus a 2-byte CRC per (up to) 16-octet data block.
     */
    public static function frameLength(int $userDataLen): int
    {
        $blocks = intdiv($userDataLen + 15, 16); // ceil
        return 10 + $userDataLen + $blocks * 2;
    }

    /**
     * Parses the 8-byte data-link header of $frame. Returns the addresses, decoded control bits and
     * whether the header CRC checks out, or null when the frame is too short / lacks the start bytes.
     *
     * @return array{length:int,control:int,dir:int,prm:int,fcb:int,fcv:int,function:int,dest:int,source:int,crcValid:bool}|null
     */
    public static function parseLinkHeader(string $frame): ?array
    {
        if (strlen($frame) < 10) {
            return null;
        }
        if (ord($frame[0]) !== self::START1 || ord($frame[1]) !== self::START2) {
            return null;
        }
        $length = ord($frame[2]);
        $control = ord($frame[3]);
        $dest = ord($frame[4]) | (ord($frame[5]) << 8);
        $source = ord($frame[6]) | (ord($frame[7]) << 8);
        $crc = ord($frame[8]) | (ord($frame[9]) << 8);

        return [
            'length' => $length,
            'control' => $control,
            'dir' => ($control >> 7) & 1,
            'prm' => ($control >> 6) & 1,
            'fcb' => ($control >> 5) & 1,
            'fcv' => ($control >> 4) & 1,
            'function' => $control & 0x0F,
            'dest' => $dest,
            'source' => $source,
            'crcValid' => $crc === self::dnp3Crc(substr($frame, 0, 8)),
        ];
    }

    /**
     * Strips the per-block CRCs from a frame's user-data region and returns the contiguous transport +
     * application bytes. Returns null when the frame is truncated. The block CRCs are not verified —
     * leniency, so a scanner sending bad CRCs is still captured.
     */
    public static function stripBlockCrcs(string $frame, int $userDataLen): ?string
    {
        $off = 10; // past the 8-byte header and its 2-byte CRC
        $out = '';
        $remaining = $userDataLen;
        $n = strlen($frame);

        while ($remaining > 0) {
            $chunk = min(16, $remaining);
            if ($off + $chunk + 2 > $n) {
                return null;
            }
            $out .= substr($frame, $off, $chunk);
            $off += $chunk + 2; // skip the block CRC
            $remaining -= $chunk;
        }

        return $out;
    }

    /**
     * Parses an application fragment (transport byte + application header + object headers).
     *
     * @return array{transport:int,appControl:int,seq:int,function:int,objects:string}|null
     */
    public static function parseApplication(string $userData): ?array
    {
        if (strlen($userData) < 3) {
            return null; // transport(1) + application control(1) + function code(1)
        }
        $transport = ord($userData[0]);
        $app = substr($userData, 1);
        $appControl = ord($app[0]);

        return [
            'transport' => $transport,
            'appControl' => $appControl,
            'seq' => $appControl & 0x0F,
            'function' => ord($app[1]),
            'objects' => substr($app, 2),
        ];
    }

    /**
     * Walks the object headers of an application request, capturing each group/variation/qualifier.
     * A READ request carries header-only objects (no point data between them), so $walkAll steps over
     * every one; for other functions only the first header is captured, since inline point data would
     * otherwise be misparsed.
     *
     * @return list<array{group:int,variation:int,qualifier:int}>
     */
    public static function parseObjectHeaders(string $objects, bool $walkAll): array
    {
        $out = [];
        $off = 0;
        $n = strlen($objects);
        $limit = $walkAll ? 32 : 1;

        while ($off + 3 <= $n && count($out) < $limit) {
            $group = ord($objects[$off]);
            $variation = ord($objects[$off + 1]);
            $qualifier = ord($objects[$off + 2]);
            $off += 3;
            $out[] = ['group' => $group, 'variation' => $variation, 'qualifier' => $qualifier];

            $rangeSize = self::rangeFieldSize($qualifier);
            if ($rangeSize < 0 || $off + $rangeSize > $n) {
                break; // unknown qualifier or truncated range field — stop cleanly
            }
            $off += $rangeSize;

            if (!$walkAll) {
                break;
            }
        }

        return $out;
    }

    /** Byte length of the range field implied by a qualifier's range-specifier nibble, or -1 if unknown. */
    private static function rangeFieldSize(int $qualifier): int
    {
        return match ($qualifier & 0x0F) {
            0x0, 0x3 => 2, // 1-octet start + stop
            0x1, 0x4 => 4, // 2-octet start + stop
            0x2, 0x5 => 8, // 4-octet start + stop
            0x6 => 0,      // all objects, no range field
            0x7 => 1,      // 1-octet count
            0x8 => 2,      // 2-octet count
            0x9 => 4,      // 4-octet count
            default => -1, // free-format / reserved — cannot size the field
        };
    }

    /**
     * CRC-16/DNP over $data: reflected, polynomial 0x3D65 (reversed 0xA6BC), init 0x0000, final
     * complement. Used for both the header CRC and every 16-octet data-block CRC.
     */
    public static function dnp3Crc(string $data): int
    {
        $crc = 0x0000;
        $n = strlen($data);
        for ($i = 0; $i < $n; $i++) {
            $crc ^= ord($data[$i]);
            for ($j = 0; $j < 8; $j++) {
                if ($crc & 0x0001) {
                    $crc = (($crc >> 1) ^ 0xA6BC) & 0xFFFF;
                } else {
                    $crc = ($crc >> 1) & 0xFFFF;
                }
            }
        }

        return (~$crc) & 0xFFFF;
    }

    /** The two CRC octets for $data, low octet first (DNP3 transmits the CRC little-endian). */
    private static function crcBytesLe(string $data): string
    {
        $crc = self::dnp3Crc($data);

        return chr($crc & 0xFF) . chr(($crc >> 8) & 0xFF);
    }

    /** Splits user data into 16-octet blocks, appending each block's CRC. */
    private static function addBlockCrcs(string $userData): string
    {
        $out = '';
        $len = strlen($userData);
        for ($off = 0; $off < $len; $off += 16) {
            $block = substr($userData, $off, 16);
            $out .= $block . self::crcBytesLe($block);
        }

        return $out;
    }

    // ---- Naming (intel readability) ------------------------------------------------------------

    /**
     * A compact description of the object headers an attacker enumerated: class-0/1/2/3 for the class
     * objects (group 60), else "g<group>v<variation>".
     *
     * @param list<array{group:int,variation:int,qualifier:int}> $objects
     */
    public static function describeObjects(array $objects): string
    {
        if ($objects === []) {
            return '(none)';
        }
        $parts = [];
        foreach (array_slice($objects, 0, 16) as $o) {
            $g = $o['group'];
            $v = $o['variation'];
            if ($g === 60 && $v >= 1 && $v <= 4) {
                $parts[] = 'class' . ($v - 1);
            } else {
                $parts[] = sprintf('g%dv%d', $g, $v);
            }
        }

        return implode(', ', $parts);
    }

    private static function linkFunctionName(int $prm, int $func): string
    {
        if ($prm === 1) {
            return match ($func) {
                self::LINK_RESET_LINK_STATES => 'RESET_LINK_STATES',
                self::LINK_RESET_USER_PROCESS => 'RESET_USER_PROCESS',
                self::LINK_TEST_LINK_STATES => 'TEST_LINK_STATES',
                self::LINK_CONFIRMED_USER_DATA => 'CONFIRMED_USER_DATA',
                self::LINK_UNCONFIRMED_USER_DATA => 'UNCONFIRMED_USER_DATA',
                self::LINK_REQUEST_LINK_STATUS => 'REQUEST_LINK_STATUS',
                default => sprintf('LINK_0x%X', $func),
            };
        }

        return match ($func) {
            0x0 => 'ACK',
            0x1 => 'NACK',
            0xB => 'LINK_STATUS',
            0xF => 'NOT_SUPPORTED',
            default => sprintf('SEC_0x%X', $func),
        };
    }

    private static function appFunctionName(int $func): string
    {
        return match ($func) {
            0x00 => 'CONFIRM',
            0x01 => 'READ',
            0x02 => 'WRITE',
            0x03 => 'SELECT',
            0x04 => 'OPERATE',
            0x05 => 'DIRECT_OPERATE',
            0x06 => 'DIRECT_OPERATE_NR',
            0x07 => 'IMMED_FREEZE',
            0x08 => 'IMMED_FREEZE_NR',
            0x09 => 'FREEZE_CLEAR',
            0x0A => 'FREEZE_CLEAR_NR',
            0x0B => 'FREEZE_AT_TIME',
            0x0C => 'FREEZE_AT_TIME_NR',
            0x0D => 'COLD_RESTART',
            0x0E => 'WARM_RESTART',
            0x0F => 'INITIALIZE_DATA',
            0x10 => 'INITIALIZE_APPL',
            0x11 => 'START_APPL',
            0x12 => 'STOP_APPL',
            0x13 => 'SAVE_CONFIG',
            0x14 => 'ENABLE_UNSOLICITED',
            0x15 => 'DISABLE_UNSOLICITED',
            0x16 => 'ASSIGN_CLASS',
            0x17 => 'DELAY_MEASURE',
            0x18 => 'RECORD_CURRENT_TIME',
            default => sprintf('FUNC_0x%02X', $func),
        };
    }

    /** Severity for an application function: control / restart commands rank highest. */
    private static function appSeverity(int $func): string
    {
        return match ($func) {
            0x02, 0x03, 0x04, 0x05, 0x06 => 'critical', // write / select / operate / direct-operate
            0x0D, 0x0E => 'critical',                   // cold / warm restart
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C => 'high', // freeze variants
            0x0F, 0x10, 0x11, 0x12, 0x13 => 'high',     // initialize / application control / save config
            0x00 => 'low',                              // confirm
            default => 'medium',
        };
    }

    // ---- Logging -------------------------------------------------------------------------------

    /**
     * @param array{source:int,dest:int,function:int,crcValid:bool,prm:int,...} $link
     */
    private function logLink(Dnp3Session $s, array $link, string $severity): void
    {
        $this->logEvent([
            'event' => 'dnp3_link',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $severity,
            'path' => sprintf(
                'DNP3 link %s src=%d dest=%d%s',
                self::linkFunctionName($link['prm'], $link['function']),
                $link['source'],
                $link['dest'],
                $link['crcValid'] ? '' : ' crc=bad'
            ),
            'src_addr' => $link['source'],
            'dest_addr' => $link['dest'],
            'link_function' => self::linkFunctionName($link['prm'], $link['function']),
        ]);
    }

    private function logUnknown(Dnp3Session $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'dnp3_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'DNP3 unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'DNP3';
        $entry['proto'] = 'dnp3';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        ($this->logger)($entry);
    }

    /** Records a per-connection fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => self::DEFAULT_PORT,
                'path' => 'DNP3 internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : self::DEFAULT_PORT;
    }
}
