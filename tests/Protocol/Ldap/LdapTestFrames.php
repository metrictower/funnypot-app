<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ldap;

/**
 * BER byte builders for the LDAP tests: LDAPMessage wrapping plus the bind, search and unbind
 * protocolOps a scanner would send, and the handful of Filter choices the honeypot renders. Kept
 * minimal — just enough structure for the parser to exercise every field it reads.
 */
trait LdapTestFrames
{
    /** BER TLV with short/long definite length. */
    private static function tlv(int $tag, string $value): string
    {
        return chr($tag) . self::berLen(strlen($value)) . $value;
    }

    private static function berLen(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $bytes = '';
        while ($n > 0) {
            $bytes = chr($n & 0xFF) . $bytes;
            $n >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function intVal(int $n): string
    {
        if ($n === 0) {
            $bytes = "\x00";
        } else {
            $bytes = '';
            $v = $n;
            while ($v > 0) {
                $bytes = chr($v & 0xFF) . $bytes;
                $v >>= 8;
            }
            if (ord($bytes[0]) & 0x80) {
                $bytes = "\x00" . $bytes;
            }
        }

        return self::tlv(0x02, $bytes);
    }

    private static function enumVal(int $n): string
    {
        return self::tlv(0x0A, $n === 0 ? "\x00" : chr($n));
    }

    private static function octet(string $s): string
    {
        return self::tlv(0x04, $s);
    }

    private static function boolVal(bool $b): string
    {
        return self::tlv(0x01, $b ? "\xFF" : "\x00");
    }

    /** LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp }. */
    private static function ldapMessage(int $messageId, string $protocolOp): string
    {
        return self::tlv(0x30, self::intVal($messageId) . $protocolOp);
    }

    /** bindRequest with simple ([0]) authentication carrying the password. */
    private static function simpleBind(int $messageId, string $dn, string $password, int $version = 3): string
    {
        $op = self::tlv(0x60, self::intVal($version) . self::octet($dn) . self::tlv(0x80, $password));

        return self::ldapMessage($messageId, $op);
    }

    /** bindRequest with SASL ([3]) authentication carrying the mechanism name. */
    private static function saslBind(int $messageId, string $dn, string $mechanism, int $version = 3): string
    {
        $sasl = self::tlv(0xA3, self::octet($mechanism));
        $op = self::tlv(0x60, self::intVal($version) . self::octet($dn) . $sasl);

        return self::ldapMessage($messageId, $op);
    }

    /**
     * searchRequest carrying a pre-built Filter BER blob.
     */
    private static function searchRequest(int $messageId, string $base, string $filter, int $scope = 2): string
    {
        $op = self::tlv(
            0x63,
            self::octet($base)
            . self::enumVal($scope)   // scope
            . self::enumVal(0)        // derefAliases = neverDerefAliases
            . self::intVal(0)         // sizeLimit
            . self::intVal(0)         // timeLimit
            . self::boolVal(false)    // typesOnly
            . $filter
            . self::tlv(0x30, '')     // attributes: empty SEQUENCE
        );

        return self::ldapMessage($messageId, $op);
    }

    /** unbindRequest ::= [APPLICATION 2] NULL. */
    private static function unbindRequest(int $messageId): string
    {
        return self::ldapMessage($messageId, self::tlv(0x42, ''));
    }

    // ---- Filter builders (RFC 4511 4.5.1) ----------------------------------------------------

    /** equalityMatch [3] { attr, value }. */
    private static function equalityFilter(string $attr, string $value): string
    {
        return self::tlv(0xA3, self::octet($attr) . self::octet($value));
    }

    /** present [7] attributeDescription. */
    private static function presentFilter(string $attr): string
    {
        return self::tlv(0x87, $attr);
    }

    /** and [0] SET OF Filter. */
    private static function andFilter(string ...$filters): string
    {
        return self::tlv(0xA0, implode('', $filters));
    }

    /** or [1] SET OF Filter. */
    private static function orFilter(string ...$filters): string
    {
        return self::tlv(0xA1, implode('', $filters));
    }

    /** substrings [4] { type, { initial/any/final } }. */
    private static function substringFilter(string $attr, ?string $initial, array $anys, ?string $final): string
    {
        $subs = '';
        if ($initial !== null) {
            $subs .= self::tlv(0x80, $initial);
        }
        foreach ($anys as $a) {
            $subs .= self::tlv(0x81, $a);
        }
        if ($final !== null) {
            $subs .= self::tlv(0x82, $final);
        }

        return self::tlv(0xA4, self::octet($attr) . self::tlv(0x30, $subs));
    }
}
