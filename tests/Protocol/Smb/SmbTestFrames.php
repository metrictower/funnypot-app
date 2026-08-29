<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Smb;

/**
 * Byte builders for the SMB tests: NetBIOS framing, SMB2 request headers, and the NTLMSSP
 * NEGOTIATE / AUTHENTICATE messages a scanner would send. Kept deliberately minimal — just enough
 * structure for the honeypot's parsers to exercise every field it reads.
 */
trait SmbTestFrames
{
    /** NetBIOS Session Service wrap: type 0x00 + 24-bit big-endian length. */
    private static function nbss(string $payload): string
    {
        $len = strlen($payload);

        return chr(0x00) . chr(($len >> 16) & 0xFF) . chr(($len >> 8) & 0xFF) . chr($len & 0xFF) . $payload;
    }

    /** 64-byte SMB2 client request header (flags = 0, i.e. client -> server). */
    private static function smb2ReqHeader(int $command, string $messageId, string $sessionId = "\x00\x00\x00\x00\x00\x00\x00\x00"): string
    {
        return "\xFESMB"
            . pack('v', 64)   // StructureSize
            . pack('v', 0)    // CreditCharge
            . pack('V', 0)    // Status
            . pack('v', $command)
            . pack('v', 1)    // CreditRequest
            . pack('V', 0)    // Flags (client -> server)
            . pack('V', 0)    // NextCommand
            . substr($messageId . str_repeat("\x00", 8), 0, 8)
            . pack('V', 0)    // Reserved
            . pack('V', 0)    // TreeId
            . substr($sessionId . str_repeat("\x00", 8), 0, 8)
            . str_repeat("\x00", 16); // Signature
    }

    /**
     * SMB2 NEGOTIATE request wrapped in NetBIOS framing.
     *
     * @param list<int> $dialects
     */
    private static function negotiateRequest(array $dialects, string $clientGuid, string $messageId = "\x01\x00\x00\x00\x00\x00\x00\x00"): string
    {
        $body = pack('v', 36)                    // StructureSize
            . pack('v', count($dialects))        // DialectCount
            . pack('v', 1)                        // SecurityMode
            . pack('v', 0)                        // Reserved
            . pack('V', 0)                        // Capabilities
            . substr($clientGuid . str_repeat("\x00", 16), 0, 16) // ClientGuid
            . str_repeat("\x00", 8);              // ClientStartTime / negotiate-context fields
        foreach ($dialects as $d) {
            $body .= pack('v', $d);
        }

        return self::nbss(self::smb2ReqHeader(0x0000, $messageId) . $body);
    }

    /** SMB2 SESSION_SETUP request carrying a security buffer (the SPNEGO/NTLMSSP token, raw here). */
    private static function sessionSetupRequest(string $securityBuffer, string $messageId, string $sessionId = "\x00\x00\x00\x00\x00\x00\x00\x00"): string
    {
        $secOffset = 64 + 24; // header + 24-byte fixed session-setup body
        $body = pack('v', 25)          // StructureSize
            . pack('C', 0)             // Flags
            . pack('C', 1)             // SecurityMode
            . pack('V', 0)             // Capabilities
            . pack('V', 0)             // Channel
            . pack('v', $secOffset)    // SecurityBufferOffset
            . pack('v', strlen($securityBuffer)) // SecurityBufferLength
            . pack('P', 0)             // PreviousSessionId
            . $securityBuffer;

        return self::nbss(self::smb2ReqHeader(0x0001, $messageId, $sessionId) . $body);
    }

    /** Minimal NTLMSSP NEGOTIATE (Type 1) — only the signature + type are inspected by the server. */
    private static function ntlmNegotiate(): string
    {
        return "NTLMSSP\x00"
            . pack('V', 1)             // NEGOTIATE
            . pack('V', 0x00088207)    // NegotiateFlags (unicode + NTLM + extended security etc.)
            . str_repeat("\x00", 8)    // DomainNameFields
            . str_repeat("\x00", 8);   // WorkstationFields
    }

    /** NTLMSSP AUTHENTICATE (Type 3) with UTF-16LE domain/user/workstation and an NT response. */
    private static function ntlmAuthenticate(string $user, string $domain, string $workstation, string $ntResp): string
    {
        $u = static function (string $s): string {
            $out = '';
            $len = strlen($s);
            for ($i = 0; $i < $len; $i++) {
                $out .= $s[$i] . "\x00";
            }

            return $out;
        };

        $domainU = $u($domain);
        $userU = $u($user);
        $wsU = $u($workstation);

        $payloadStart = 64; // fixed part is 64 bytes; no Version field here
        $lmOff = $payloadStart;
        $ntOff = $payloadStart; // LM empty
        $domOff = $ntOff + strlen($ntResp);
        $userOff = $domOff + strlen($domainU);
        $wsOff = $userOff + strlen($userU);

        $field = static fn (int $len, int $off): string => pack('v', $len) . pack('v', $len) . pack('V', $off);

        $header = "NTLMSSP\x00"
            . pack('V', 3)                               // AUTHENTICATE
            . $field(0, $lmOff)                          // LmChallengeResponse (empty)
            . $field(strlen($ntResp), $ntOff)            // NtChallengeResponse
            . $field(strlen($domainU), $domOff)          // DomainName
            . $field(strlen($userU), $userOff)           // UserName
            . $field(strlen($wsU), $wsOff)               // Workstation
            . $field(0, $payloadStart)                   // EncryptedRandomSessionKey (empty)
            . pack('V', 0x00000001);                     // NegotiateFlags (UNICODE)

        return $header . $ntResp . $domainU . $userU . $wsU;
    }
}
