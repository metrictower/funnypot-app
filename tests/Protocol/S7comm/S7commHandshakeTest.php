<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\S7comm;

use Funnypot\Protocol\S7comm\S7commConfig;
use Funnypot\Protocol\S7comm\S7commServer;
use Funnypot\Protocol\S7comm\S7commSession;
use PHPUnit\Framework\TestCase;

final class S7commHandshakeTest extends TestCase
{
    use S7commTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?S7commConfig $config = null): S7commServer
    {
        $this->events = [];

        return new S7commServer($config ?? new S7commConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }

    public function test_connection_request_captures_tsaps_and_confirms(): void
    {
        $server = $this->newServer();
        $session = new S7commSession('203.0.113.5', 50000, 1);
        $session->inbuf .= self::connectionRequest(srcRef: 0x0004, dstRef: 0x0000, srcTsap: 0x0100, dstTsap: 0x0102);
        $server->processInbound($session);

        self::assertSame(0x0100, $session->srcTsap);
        self::assertSame(0x0102, $session->dstTsap);
        self::assertSame(S7commSession::STATE_CONNECTED, $session->state);

        $connect = $this->eventOfType('s7_connect');
        self::assertNotNull($connect);
        self::assertSame('0x0102', $connect['dst_tsap']);

        // Connection Confirm: TPKT then COTP CC (0xD0).
        $cc = $session->outbuf;
        self::assertSame(0x03, ord($cc[0]));
        self::assertSame(0xd0, ord($cc[5]));
        // DST-REF echoes the client's SRC-REF; SRC-REF is the server's assigned reference.
        self::assertSame(0x0004, (ord($cc[6]) << 8) | ord($cc[7]));
        self::assertSame(0x0001, (ord($cc[8]) << 8) | ord($cc[9]));
        // The confirm mirrors the TSAPs with source and destination swapped.
        self::assertStringContainsString("\xc1\x02\x01\x02", $cc, 'CC src-TSAP = client dst-TSAP');
        self::assertStringContainsString("\xc2\x02\x01\x00", $cc, 'CC dst-TSAP = client src-TSAP');
    }

    public function test_setup_communication_negotiates_pdu_size_down_to_max(): void
    {
        $server = $this->newServer(); // default maxPduSize = 240
        $session = new S7commSession('203.0.113.5', 50000, 1);
        $session->inbuf .= self::connectionRequest();
        $server->processInbound($session);
        $session->outbuf = '';

        // Client asks for 480; the CPU negotiates down to its own maximum of 240.
        $session->inbuf .= self::setupCommunication(reqPdu: 480);
        $server->processInbound($session);

        self::assertSame(240, $session->negotiatedPduSize);

        $job = $this->eventOfType('s7_job');
        self::assertNotNull($job);
        self::assertSame('setup', $job['function']);
        self::assertStringContainsString('negotiated_pdu=240', $job['path']);

        // Response: Ack_Data (ROSCTR 0x03) whose Setup param carries the negotiated PDU size.
        $resp = $session->outbuf;
        self::assertSame(0x32, ord($resp[7]), 'S7 protocol id');
        self::assertSame(0x03, ord($resp[8]), 'ROSCTR Ack_Data');
        // 12-byte header for Ack_Data, then the 8-byte Setup param at offset 7+12 = 19.
        self::assertSame(0xf0, ord($resp[19]), 'Setup Communication function');
        self::assertSame(240, (ord($resp[25]) << 8) | ord($resp[26]), 'negotiated PDU size on the wire');
    }

    public function test_full_sequence_connect_setup_then_read(): void
    {
        $server = $this->newServer();
        $session = new S7commSession('198.51.100.7', 44818, 1);

        // COTP CR -> CC.
        $session->inbuf .= self::connectionRequest();
        $server->processInbound($session);
        self::assertSame(S7commSession::STATE_CONNECTED, $session->state);
        $session->outbuf = '';

        // Setup Communication -> Ack_Data.
        $session->inbuf .= self::setupCommunication(reqPdu: 240);
        $server->processInbound($session);
        self::assertSame(240, $session->negotiatedPduSize);
        $session->outbuf = '';

        // Read Var: 10 bytes of DB1 starting at DBB0.
        $session->inbuf .= self::readVar(transport: 0x02, count: 10, db: 1, area: 0x84, byte: 0);
        $server->processInbound($session);

        self::assertCount(1, $session->reads);
        self::assertSame('read', $session->reads[0]['op']);
        self::assertSame(0x84, $session->reads[0]['area']);
        self::assertSame(1, $session->reads[0]['db']);
        self::assertSame(0, $session->reads[0]['byte']);
        self::assertSame(10, $session->reads[0]['count']);

        // Read response: Ack_Data, function 0x04, one data item with success code 0xFF and zero data.
        $resp = $session->outbuf;
        self::assertSame(0x03, ord($resp[8]), 'ROSCTR Ack_Data');
        self::assertSame(0x04, ord($resp[19]), 'Read Var function echoed');
        self::assertSame(0x01, ord($resp[20]), 'item count');
        self::assertSame(0xff, ord($resp[21]), 'data item return code = success');
        // Inert: the returned data bytes are all zero (never real process memory).
        $dataBytes = substr($resp, 25, 10);
        self::assertSame(str_repeat("\x00", 10), $dataBytes);
    }

    public function test_data_before_connection_request_is_rejected(): void
    {
        // An S7 Job arriving before the COTP handshake is out of sequence: log and drop, never crash.
        $server = $this->newServer();
        $session = new S7commSession('192.0.2.9', 5000, 1);
        $session->inbuf .= self::setupCommunication();
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('s7_unknown'));
    }

    public function test_non_tpkt_input_closes_cleanly(): void
    {
        // A TLS ClientHello (0x16) or other junk is unmodelled: record and drop.
        $server = $this->newServer();
        $session = new S7commSession('192.0.2.1', 5000, 1);
        $session->inbuf .= "\x16\x03\x01\x00\x50" . str_repeat("\x00", 80);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('s7_unknown'));
    }

    public function test_partial_pdu_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new S7commSession('192.0.2.2', 5001, 1);

        $cr = self::connectionRequest();
        // Feed the TPKT header and a fragment first: nothing should be parsed yet.
        $session->inbuf .= substr($cr, 0, 6);
        $server->processInbound($session);
        self::assertSame(S7commSession::STATE_WAIT_COTP_CR, $session->state);
        self::assertNull($session->srcTsap);

        // Deliver the remainder: the request now parses and confirms.
        $session->inbuf .= substr($cr, 6);
        $server->processInbound($session);
        self::assertSame(S7commSession::STATE_CONNECTED, $session->state);
        self::assertSame(0x0100, $session->srcTsap);
    }

    public function test_malformed_pdu_never_escapes_process_inbound(): void
    {
        // A TPKT claiming a valid length but with a truncated/garbage COTP body must degrade, not throw.
        $server = $this->newServer();
        $session = new S7commSession('192.0.2.3', 5002, 1);
        $session->inbuf .= "\x03\x00\x00\x08\x03\xe0\xff\xff"; // TPKT len 8, bogus short CR
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('s7_unknown'));
    }
}
