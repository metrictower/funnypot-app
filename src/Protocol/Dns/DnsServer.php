<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dns;

use Funnypot\Protocol\UdpResponseBucket;

/**
 * Zero-dependency dual-stack (UDP + TCP) DNS honeypot server on port 53 (FP-0182). Binds udp:// and
 * tcp:// on one address in a single non-blocking stream_select loop (the {@see \Funnypot\Protocol\Sip\SipServer}
 * pattern): UDP for ordinary queries, TCP for AXFR and TC-retry. Decodes with {@see DnsMessage}, decides
 * with {@see DnsResponder}, and serves mirror/honeypot/sinkhole answers, a BIND CHAOS fingerprint, and a
 * canary AXFR zone.
 *
 * ANTI-AMPLIFICATION (B1, security-critical): the UDP emit path carries an UNCONDITIONAL final byte-clamp
 * — a reply is never larger than the request that triggered it, and if it would be, it is dropped. That
 * is the single chokepoint; no responder branch can turn the box into a reflector. A per-apparent-source
 * token bucket ({@see UdpResponseBucket}) further caps reply datagrams at a spoofed victim. Every
 * single-datagram UDP event is non-reportable. INERT: resolves nothing, executes nothing.
 */
final class DnsServer
{
    use UdpResponseBucket;

    private const READ_CHUNK = 65535;        // a single UDP datagram / TCP read
    private const INBUF_CAP = 65535;         // one DNS-over-TCP message never legitimately exceeds this
    private const MAX_DGRAMS_PER_TICK = 64;  // bound the UDP drain so a flood can't spin one tick
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120;

    // UdpResponseBucket knobs (resolved against self:: at the trait's call sites).
    private const UDP_RESP_BURST = 20.0;
    private const UDP_RESP_RATE = 10.0;
    private const UDP_BUCKET_MAX_IPS = 4096;
    private const UDP_RESP_SEED = 2.0;

    /** @param callable(array<string,mixed>):void $logger */
    public function __construct(
        private DnsConfig $config,
        private $logger
    ) {
    }

    /** Bind udp+tcp on $bind (e.g. "0.0.0.0:53") and serve forever. */
    public function run(string $bind): void
    {
        $udp = @stream_socket_server('udp://' . $bind, $errno, $errstr, STREAM_SERVER_BIND);
        if ($udp === false) {
            fwrite(STDERR, "funnypot-dns: cannot bind udp {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($udp, false);

        $tcp = @stream_socket_server('tcp://' . $bind, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if ($tcp === false) {
            @fclose($udp);
            fwrite(STDERR, "funnypot-dns: cannot bind tcp {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($tcp, false);

        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-dns ({$this->config->mode}, BIND {$this->config->bindVersion}) listening on {$bind} (UDP & TCP)\n");

        /** @var array<int,array{sock:resource,ip:string,inbuf:string,outbuf:string,last:int}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$udp, $tcp];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['outbuf'] !== '') {
                    $write[] = $c['sock'];
                }
            }
            $except = null;

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }
            $now = time();

            foreach ($read as $r) {
                try {
                    if ($r === $udp) {
                        $this->drainUdp($udp, $port);
                    } elseif ($r === $tcp) {
                        $this->acceptTcp($tcp, $conns, $perIp, $now);
                    } else {
                        $this->readTcp($conns, $perIp, $r, $now);
                    }
                } catch (\Throwable $e) {
                    $this->logFault('inbound', $e);
                }
            }

            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (!isset($conns[$id]) || $conns[$id]['outbuf'] === '') {
                    continue;
                }
                $written = @fwrite($w, $conns[$id]['outbuf']);
                if ($written === false) {
                    $this->closeTcp($conns, $perIp, $id);
                    continue;
                }
                $conns[$id]['outbuf'] = substr($conns[$id]['outbuf'], $written);
            }

            foreach ($conns as $id => $c) {
                if ($now - $c['last'] > self::IDLE_TIMEOUT) {
                    $this->closeTcp($conns, $perIp, $id);
                }
            }
        }
    }

    /** @param resource $udp */
    private function drainUdp($udp, int $port): void
    {
        for ($i = 0; $i < self::MAX_DGRAMS_PER_TICK; $i++) {
            $peer = '';
            $data = @stream_socket_recvfrom($udp, self::READ_CHUNK, 0, $peer);
            if ($data === false || $data === '' || $peer === '') {
                break;
            }
            [$ip] = self::splitAddr((string) $peer);
            $requestLen = \strlen($data);

            $query = DnsMessage::decodeQuery($data);
            if ($query === null) {
                continue; // malformed — drop silently
            }
            $r = DnsResponder::respond($query, $ip, $requestLen, DnsResponder::TRANSPORT_UDP, $this->config);

            // UNCONDITIONAL final anti-amplification clamp — the single chokepoint. If a reply is somehow
            // larger than the request (no responder branch should produce this), drop it entirely.
            $bytes = self::clampReply($r['bytes'], $requestLen);
            if ($bytes === '') {
                $this->log($r['event'], $ip, $port, $query, false);
                continue;
            }

            // Per-apparent-source token bucket: a spoofed victim's bucket drains and the reply is dropped.
            if (!$this->udpResponseAllowed($ip)) {
                continue;
            }
            @stream_socket_sendto($udp, $bytes, 0, (string) $peer);
            $this->log($r['event'], $ip, $port, $query, false); // UDP events are never reportable
        }
    }

    /**
     * @param resource $tcp
     * @param array<int,array{sock:resource,ip:string,inbuf:string,outbuf:string,last:int}> $conns
     * @param array<string,int> $perIp
     */
    private function acceptTcp($tcp, array &$conns, array &$perIp, int $now): void
    {
        $sock = @stream_socket_accept($tcp, 0);
        if ($sock === false) {
            return;
        }
        stream_set_blocking($sock, false);
        [$ip] = self::splitAddr((string) @stream_socket_get_name($sock, true));

        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }
        $id = get_resource_id($sock);
        $conns[$id] = ['sock' => $sock, 'ip' => $ip, 'inbuf' => '', 'outbuf' => '', 'last' => $now];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;
    }

    /**
     * @param array<int,array{sock:resource,ip:string,inbuf:string,outbuf:string,last:int}> $conns
     * @param array<string,int> $perIp
     * @param resource $sock
     */
    private function readTcp(array &$conns, array &$perIp, $sock, int $now): void
    {
        $id = get_resource_id($sock);
        if (!isset($conns[$id])) {
            return;
        }
        $data = @fread($sock, self::READ_CHUNK);
        if ($data === false || ($data === '' && feof($sock))) {
            $this->closeTcp($conns, $perIp, $id);

            return;
        }
        if ($data === '') {
            return;
        }
        $conns[$id]['last'] = $now;
        $conns[$id]['inbuf'] .= $data;
        if (\strlen($conns[$id]['inbuf']) > self::INBUF_CAP) {
            $this->closeTcp($conns, $perIp, $id);

            return;
        }

        // DNS-over-TCP framing: 2-byte big-endian length prefix, then the message.
        while (\strlen($conns[$id]['inbuf']) >= 2) {
            $msgLen = (\ord($conns[$id]['inbuf'][0]) << 8) | \ord($conns[$id]['inbuf'][1]);
            if (\strlen($conns[$id]['inbuf']) < 2 + $msgLen) {
                break; // wait for the rest
            }
            $msg = \substr($conns[$id]['inbuf'], 2, $msgLen);
            $conns[$id]['inbuf'] = \substr($conns[$id]['inbuf'], 2 + $msgLen);

            $query = DnsMessage::decodeQuery($msg);
            if ($query === null) {
                continue;
            }
            $r = DnsResponder::respond($query, $conns[$id]['ip'], $msgLen, DnsResponder::TRANSPORT_TCP, $this->config);
            // TCP reply is framed with its own 2-byte length prefix.
            $conns[$id]['outbuf'] .= \chr((\strlen($r['bytes']) >> 8) & 0xFF) . \chr(\strlen($r['bytes']) & 0xFF) . $r['bytes'];
            $this->log($r['event'], $conns[$id]['ip'], 53, $query, $r['reportable']);
        }
    }

    /**
     * @param array<int,array{sock:resource,ip:string,inbuf:string,outbuf:string,last:int}> $conns
     * @param array<string,int> $perIp
     */
    private function closeTcp(array &$conns, array &$perIp, int $id): void
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

    private function log(string $event, string $ip, int $port, DnsQuery $q, bool $reportable): void
    {
        ($this->logger)([
            'event' => $event,
            'ip' => $ip,
            'port' => $port,
            'proto' => 'dns',
            'path' => $q->qname === '' ? '<root>' : $q->qname,
            'qtype' => $q->qtype,
            'reportable' => $reportable,
        ]);
    }

    private function logFault(string $where, \Throwable $e): void
    {
        ($this->logger)([
            'event' => 'error',
            'proto' => 'dns',
            'path' => "DNS fault ({$where}): " . $e->getMessage(),
            'reportable' => false,
        ]);
    }

    /**
     * The unconditional UDP anti-amplification clamp as a pure function (so it is unit-testable without a
     * socket): a reply strictly larger than the request it answers is dropped to '' — the honeypot can
     * never emit more UDP bytes than it received, whatever a responder branch produced.
     */
    public static function clampReply(string $reply, int $requestLen): string
    {
        return \strlen($reply) > $requestLen ? '' : $reply;
    }

    /** @return array{0:string,1:int} */
    private static function splitAddr(string $addr): array
    {
        $lastColon = strrpos($addr, ':');
        if ($lastColon !== false) {
            return [substr($addr, 0, $lastColon), (int) substr($addr, $lastColon + 1)];
        }

        return [$addr, 53];
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 53;
    }
}
