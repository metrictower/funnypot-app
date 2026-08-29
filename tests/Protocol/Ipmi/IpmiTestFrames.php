<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ipmi;

/**
 * Byte builders for the IPMI tests: RMCP envelopes, the IPMI 1.5 session header + LAN message, and the
 * IPMI 2.0 RMCP+ Open Session / RAKP payloads a BMC scanner would send. Kept minimal — just enough
 * structure for the honeypot's parser to exercise every field it reads.
 *
 * Several builders take an optional trailing-padding length. A real believable BMC reply (auth-cap or
 * RAKP Message 2) is a few bytes larger than a minimal probe, so padding inflates the request past the
 * anti-amplification cap to let the reply through — the same trick the BACnet tests use with a routed
 * envelope. The IPMI session header carries an explicit message length, so trailing padding is ignored
 * by the parser.
 */
trait IpmiTestFrames
{
    private static function csum(string $bytes): string
    {
        $sum = 0;
        for ($i = 0, $n = strlen($bytes); $i < $n; $i++) {
            $sum += ord($bytes[$i]);
        }

        return chr((0x100 - ($sum & 0xFF)) & 0xFF);
    }

    /** An IPMI LAN request message: BMC responder, remote-console requester, both checksums. */
    private static function ipmiLanRequest(int $netFn, int $rqSeqLun, int $cmd, string $data): string
    {
        $head = chr(0x20) . chr(($netFn << 2) & 0xFF); // rsAddr = BMC, netFn/LUN
        $chk1 = self::csum($head);
        $tail = chr(0x81) . chr($rqSeqLun & 0xFF) . chr($cmd & 0xFF) . $data; // rqAddr = console
        $chk2 = self::csum($tail);

        return $head . $chk1 . $tail . $chk2;
    }

    /** Wraps an IPMI LAN message in an IPMI 1.5 session header (auth none) + RMCP/IPMI header. */
    private static function wrapIpmi15(string $msg): string
    {
        return "\x06\x00\xff\x07" . "\x00" . "\x00\x00\x00\x00" . "\x00\x00\x00\x00" . chr(strlen($msg)) . $msg;
    }

    /** Wraps a payload in an RMCP+ (IPMI 2.0) session header + RMCP/IPMI header. */
    private static function wrapRmcpPlus(int $payloadType, string $payload): string
    {
        return "\x06\x00\xff\x07" . "\x06" . chr($payloadType & 0x3F) . "\x00\x00\x00\x00" . "\x00\x00\x00\x00"
            . pack('v', strlen($payload)) . $payload;
    }

    /** Get Channel Authentication Capabilities request (channel 0x0e + get-v2-ext, ADMIN priv). */
    private static function getChannelAuthCapDatagram(int $pad = 0): string
    {
        $msg = self::ipmiLanRequest(0x06, 0x04, 0x38, "\x8e\x04");

        return self::wrapIpmi15($msg) . str_repeat("\x00", $pad);
    }

    /** Get Session Challenge request carrying an auth type and the username being probed. */
    private static function getSessionChallengeDatagram(string $username): string
    {
        $data = chr(0x02) . substr($username . str_repeat("\x00", 16), 0, 16); // auth type MD5 + 16-byte user
        $msg = self::ipmiLanRequest(0x06, 0x08, 0x39, $data);

        return self::wrapIpmi15($msg);
    }

    /** Activate Session request (a bare App command; its body is irrelevant to capture). */
    private static function activateSessionDatagram(): string
    {
        $msg = self::ipmiLanRequest(0x06, 0x0c, 0x3a, "\x02\x04" . str_repeat("\x00", 18));

        return self::wrapIpmi15($msg);
    }

    private static function openSessionRequestPayload(int $tag, int $maxPriv, string $consoleSid4): string
    {
        $auth = "\x00\x00\x00\x08\x01\x00\x00\x00";
        $integ = "\x01\x00\x00\x08\x01\x00\x00\x00";
        $conf = "\x02\x00\x00\x08\x01\x00\x00\x00";

        return chr($tag) . chr($maxPriv & 0x0F) . "\x00\x00" . $consoleSid4 . $auth . $integ . $conf;
    }

    private static function openSessionDatagram(int $tag = 0, int $maxPriv = 4, string $consoleSid4 = "\xa0\xa1\xa2\xa3"): string
    {
        return self::wrapRmcpPlus(0x10, self::openSessionRequestPayload($tag, $maxPriv, $consoleSid4));
    }

    private static function rakp1Payload(int $tag, string $bmcSid4, string $consoleRandom16, int $priv, string $username): string
    {
        return chr($tag) . "\x00\x00\x00" . $bmcSid4 . $consoleRandom16 . chr($priv & 0x1F) . "\x00\x00"
            . chr(strlen($username)) . $username;
    }

    private static function rakp1Datagram(string $username, int $priv = 4, int $pad = 0): string
    {
        $payload = self::rakp1Payload(0, "\xb0\xb1\xb2\xb3", str_repeat("\x11", 16), $priv, $username);

        return self::wrapRmcpPlus(0x12, $payload) . str_repeat("\x00", $pad);
    }

    private static function rakp3Datagram(): string
    {
        $payload = chr(0) . "\x00\x00\x00" . "\xb0\xb1\xb2\xb3" . str_repeat("\x22", 20);

        return self::wrapRmcpPlus(0x14, $payload);
    }
}
