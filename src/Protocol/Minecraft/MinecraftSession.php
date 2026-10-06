<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Minecraft;

/**
 * Per-connection Minecraft state machine (FP-0206). Fed inbound bytes, it frames packets ({@see VarInt}),
 * walks Handshake -> Status/Login, answers Server-List-Ping with the persona JSON, echoes Ping/Pong, and
 * scans the handshake server-address + login username for Log4Shell ({@see MinecraftThreat}).
 *
 * INERT: a captured JNDI C2 is logged, never resolved/dialed. The login path reads the username only to
 * scan it, then disconnects — no session is ever granted. A frame fault throws to the server, which closes
 * only that connection. Testable without a socket via {@see receive()}.
 */
final class MinecraftSession
{
    private const STATE_HANDSHAKE = 0;
    private const STATE_STATUS = 1;
    private const STATE_LOGIN = 2;

    private const INBUF_CAP = 65536;
    private const PACKET_CAP = 65536;

    /** @var callable(array<string,mixed>):void */
    private $logger;

    private string $inbuf = '';
    private int $state = self::STATE_HANDSHAKE;
    public bool $close = false;

    /** @param callable(array<string,mixed>):void $logger */
    public function __construct(
        private MinecraftConfig $config,
        callable $logger,
        private string $ip = ''
    ) {
        $this->logger = $logger;
    }

    /** Feed inbound bytes; return bytes to write back (possibly ''). */
    public function receive(string $bytes): string
    {
        $this->inbuf .= $bytes;
        if (\strlen($this->inbuf) > self::INBUF_CAP) {
            throw new \RuntimeException('Minecraft: inbound buffer exceeded cap');
        }

        $out = '';
        $offset = 0;
        while (true) {
            $save = $offset;
            $packet = VarInt::readPacket($this->inbuf, $offset, self::PACKET_CAP); // may throw on bad length
            if ($packet === null) {
                $offset = $save;
                break; // wait for more
            }
            $out .= $this->onPacket($packet['id'], $packet['payload']);
            if ($this->close) {
                break;
            }
        }
        $this->inbuf = \substr($this->inbuf, $offset);

        return $out;
    }

    private function onPacket(int $id, string $payload): string
    {
        if ($this->state === self::STATE_HANDSHAKE) {
            return $this->onHandshake($payload);
        }
        if ($this->state === self::STATE_STATUS) {
            if ($id === 0x00) {
                return $this->packet(0x00, VarInt::writeString($this->config->statusJson()));
            }
            if ($id === 0x01) {
                // Ping: echo the client's 8-byte long back as Pong (0x01).
                return $this->packet(0x01, \substr($payload, 0, 8));
            }

            return '';
        }
        if ($this->state === self::STATE_LOGIN) {
            return $this->onLogin($payload);
        }

        return '';
    }

    private function onHandshake(string $payload): string
    {
        $off = 0;
        $proto = VarInt::read($payload, $off);
        $addr = VarInt::readString($payload, $off, 255);
        // server port (u16 BE) then next-state VarInt
        $off += 2;
        $next = VarInt::read($payload, $off);

        $verdict = MinecraftThreat::classify([(string) $addr]);
        if ($verdict['critical']) {
            $this->logHit($verdict, 'handshake-address');
        }

        $this->state = ($next === 2) ? self::STATE_LOGIN : self::STATE_STATUS;
        if ($this->state === self::STATE_STATUS && !$verdict['critical']) {
            // Ordinary crawler ping — a low-signal recon event.
            ($this->logger)([
                'event' => MinecraftThreat::CLASS_PING,
                'ip' => $this->ip,
                'proto' => 'minecraft',
                'path' => 'server-list-ping',
                'reportable' => true,
            ]);
        }

        return '';
    }

    private function onLogin(string $payload): string
    {
        $off = 0;
        $username = VarInt::readString($payload, $off, 255);

        $verdict = MinecraftThreat::classify([(string) $username]);
        if ($verdict['critical']) {
            $this->logHit($verdict, 'login-username');
        }

        // Never grant a session — kick with a plausible reason, then close.
        $this->close = true;
        $kick = (string) \json_encode(['text' => 'Server is whitelisted.'], JSON_UNESCAPED_SLASHES);

        return $this->packet(0x00, VarInt::writeString($kick)); // login Disconnect = 0x00
    }

    private function logHit(array $verdict, string $where): void
    {
        $entry = [
            'event' => MinecraftThreat::CLASS_LOG4SHELL,
            'ip' => $this->ip,
            'proto' => 'minecraft',
            'path' => $where,
            'reportable' => true,
        ];
        if ($verdict['c2'] !== null) {
            $entry['c2'] = $verdict['c2'];
        }
        if ($verdict['raw'] !== null) {
            $entry['command'] = $verdict['raw'];
            $entry['body'] = $verdict['raw'];
        }
        ($this->logger)($entry);
    }

    /** Frame a response packet: [VarInt total-length][VarInt id][data]. */
    private function packet(int $id, string $data): string
    {
        $body = VarInt::write($id) . $data;

        return VarInt::write(\strlen($body)) . $body;
    }
}
