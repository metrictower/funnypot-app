<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\RtpStreamer;
use Funnypot\Protocol\Sip\SipSession;
use PHPUnit\Framework\TestCase;

final class RtpStreamerTest extends TestCase
{
    public function test_rtp_header_structure(): void
    {
        // First packet: marker bit = true
        $hdr1 = RtpStreamer::buildHeader(1001, 50000, 1234567, true);
        $this->assertSame(12, strlen($hdr1));

        $unpacked = unpack('Cbyte0/Cbyte1/nseq/Ntimestamp/Nssrc', $hdr1);
        $this->assertSame(0x80, $unpacked['byte0']); // V=2, P=0, X=0, CC=0
        $this->assertSame(0x80, $unpacked['byte1']); // M=1, PT=0 (PCMU)
        $this->assertSame(1001, $unpacked['seq']);
        $this->assertSame(50000, $unpacked['timestamp']);
        $this->assertSame(1234567, $unpacked['ssrc']);

        // Subsequent packet: marker bit = false
        $hdr2 = RtpStreamer::buildHeader(1002, 50160, 1234567, false);
        $unpacked2 = unpack('Cbyte0/Cbyte1/nseq/Ntimestamp/Nssrc', $hdr2);
        $this->assertSame(0x00, $unpacked2['byte1']); // M=0, PT=0 (PCMU)
        $this->assertSame(1002, $unpacked2['seq']);
        $this->assertSame(50160, $unpacked2['timestamp']);
    }

    public function test_anti_reflection_blocks_mismatched_destination_ip(): void
    {
        $streamer = new RtpStreamer();
        $s = new SipSession('call-reflect-test', '203.0.113.5', 5060);

        // Attempting to forge remoteRtpIp to a victim's IP
        $s->remoteRtpIp = '198.51.100.99';
        $s->remoteRtpPort = 4000;

        // Must be rejected by RtpStreamer
        $result = $streamer->sendPacket($s, str_repeat(chr(0xff), 160));
        $this->assertFalse($result, 'RTP packet must be refused when destination IP does not equal peer IP');
        $this->assertSame(0, $s->rtpPacketsSent);
    }

    public function test_send_packet_advances_sequence_and_timestamp(): void
    {
        // A fixed media port is required now (no ephemeral fallback); a send opens the dialog socket.
        $port = self::freeUdpPort();
        $streamer = new RtpStreamer($port);
        $s = new SipSession('call-seq-test', '127.0.0.1', 5060);
        $s->remoteRtpPort = 16402;

        $startSeq = $s->rtpSeq;
        $startTimestamp = $s->rtpTimestamp;

        $payload = str_repeat(chr(0xaa), 160);
        $sent = $streamer->sendPacket($s, $payload);

        $this->assertTrue($sent);
        $this->assertSame(1, $s->rtpPacketsSent);
        $this->assertSame(($startSeq + 1) & 0xffff, $s->rtpSeq);
        $this->assertSame(($startTimestamp + 160) & 0xffffffff, $s->rtpTimestamp);
    }

    public function test_no_socket_until_a_dialog_activates_and_no_ephemeral_fallback(): void
    {
        $port = self::freeUdpPort();
        $streamer = new RtpStreamer($port);
        // Construction binds nothing; the advertised port is the configured fixed port regardless.
        $this->assertNull($streamer->getSocket());
        $this->assertSame($port, $streamer->getLocalPort());

        $this->assertTrue($streamer->activateDialog('call-a'));
        $this->assertNotNull($streamer->getSocket());

        // A second dialog shares the one socket; the last dialog to end closes it.
        $streamer->activateDialog('call-b');
        $streamer->deactivateDialog('call-a');
        $this->assertNotNull($streamer->getSocket(), 'socket stays open while another dialog is active');
        $streamer->deactivateDialog('call-b');
        $this->assertNull($streamer->getSocket(), 'the last dialog closes the media socket');
    }

    public function test_zero_port_never_binds_an_ephemeral_socket(): void
    {
        $streamer = new RtpStreamer(0);
        $this->assertFalse($streamer->activateDialog('call-x'));
        $this->assertNull($streamer->getSocket());
    }

    private static function freeUdpPort(): int
    {
        $sock = stream_socket_server('udp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND);
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);

        return (int) substr($name, strrpos($name, ':') + 1);
    }
}
