<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The closed probe id -> implementation map. Descriptors name a probe by a fixed id (never an
 * executable string); the supervisor runs the matching probe only at cutover and crash recovery
 * (heartbeat health between those moments is child liveness, not a periodic socket probe, so a
 * loopback flood never lands in the hit store). The socket seam is injectable so host tests never
 * open a real socket.
 *
 * `media-reserved-v1` is intentionally a no-op that reports healthy: an inactive RTP media port is a
 * reserved capability, not a live listener to connect to.
 */
final class ServiceHealthProbeRegistry
{
    public const PROBE_IDS = ['tcp-connect-v1', 'udp-echo-v1', 'sip-signalling-v1', 'media-reserved-v1', 'nginx-alias-v1'];

    /** @var callable(string,int,int):bool a (host, port, timeoutMs)->ok TCP connector */
    private $tcpConnector;
    /** @var callable(string,int,int):bool a (host, port, timeoutMs)->ok UDP datagram probe */
    private $udpProbe;

    /**
     * @param callable(string,int,int):bool|null $tcpConnector
     * @param callable(string,int,int):bool|null $udpProbe
     */
    public function __construct(?callable $tcpConnector = null, ?callable $udpProbe = null)
    {
        $this->tcpConnector = $tcpConnector ?? [self::class, 'defaultTcpConnect'];
        $this->udpProbe = $udpProbe ?? [self::class, 'defaultUdpProbe'];
    }

    public function has(string $probeId): bool
    {
        return in_array($probeId, self::PROBE_IDS, true);
    }

    /**
     * Run a service's probe against its own container bind on loopback. A media-reserved probe is a
     * no-op success; an unknown probe id fails closed.
     */
    public function probe(ServiceDescriptor $desc, int $timeoutMs = 3000, string $host = '127.0.0.1'): bool
    {
        return match ($desc->probeId) {
            'media-reserved-v1' => true,
            'nginx-alias-v1' => ($this->tcpConnector)($host, 80, $timeoutMs),
            'udp-echo-v1' => $this->probeFirst($desc, 'udp', $timeoutMs, $host),
            'tcp-connect-v1', 'sip-signalling-v1' => $this->probeFirst($desc, 'tcp', $timeoutMs, $host),
            default => false,
        };
    }

    private function probeFirst(ServiceDescriptor $desc, string $transport, int $timeoutMs, string $host): bool
    {
        foreach ($desc->endpoints as $ep) {
            if ($ep->isBind() && $ep->transport === $transport) {
                $fn = $transport === 'udp' ? $this->udpProbe : $this->tcpConnector;

                return $fn($host, $ep->containerPort, $timeoutMs);
            }
        }

        return false;
    }

    public static function defaultTcpConnect(string $host, int $port, int $timeoutMs): bool
    {
        $errno = 0;
        $errstr = '';
        $sock = @fsockopen($host, $port, $errno, $errstr, max(0.1, $timeoutMs / 1000));
        if ($sock === false) {
            return false;
        }
        fclose($sock);

        return true;
    }

    public static function defaultUdpProbe(string $host, int $port, int $timeoutMs): bool
    {
        // A bound UDP socket "connect" only proves a local socket exists; the real bounded-response
        // fixtures live in the UDP integration tests. Here we confirm the datagram socket is openable.
        $sock = @stream_socket_client("udp://{$host}:{$port}", $errno, $errstr, max(0.1, $timeoutMs / 1000));
        if ($sock === false) {
            return false;
        }
        fclose($sock);

        return true;
    }
}
