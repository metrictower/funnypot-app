<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dns;

/**
 * Pure DNS response logic (FP-0182). Given a decoded query + peer + request length + transport, returns
 * the response bytes, a threat-event name, and whether the event is reportable. No I/O.
 *
 * ANTI-AMPLIFICATION (the load-bearing invariant): a DNS answer is intrinsically larger than its query,
 * so over UDP any answer exceeding the request is downgraded to a TC=1 truncated, zero-answer reply
 * (question echoed, <= request size) inviting a TCP retry. The full mirror/CHAOS/sinkhole/AXFR answer is
 * therefore a TCP-path feature. {@see DnsServer} applies an unconditional final byte-clamp as the backstop.
 * Every single-datagram UDP event is non-reportable (a spoofed-victim source must never be reported).
 */
final class DnsResponder
{
    public const TRANSPORT_UDP = 'udp';
    public const TRANSPORT_TCP = 'tcp';

    private const MAX_ZONE_RECORDS = 64; // bound the AXFR stream

    /**
     * @return array{bytes: string, event: string, reportable: bool}
     */
    public static function respond(DnsQuery $q, string $peerIp, int $requestLen, string $transport, DnsConfig $cfg): array
    {
        $udp = $transport === self::TRANSPORT_UDP;

        // AXFR: TCP streams the canary zone; over UDP it is the worst-case amplifier -> REFUSED, never zone.
        if ($q->qtype === DnsMessage::TYPE_AXFR) {
            if ($udp) {
                return self::clampUdp($q, self::refused($q), 'dns_axfr', $requestLen, $udp);
            }

            return ['bytes' => self::axfrZone($q, $cfg), 'event' => 'dns_axfr', 'reportable' => true];
        }

        // CHAOS version.bind / hostname.bind / id.server.
        if ($q->isChaos()) {
            $full = self::chaos($q, $cfg);

            return self::clampUdp($q, $full, 'dns_chaos', $requestLen, $udp);
        }

        // Amplification-prone classes (ANY / TXT / root-zone / large EDNS): minimal refusal.
        if ($q->isAmplificationProne()) {
            return self::clampUdp($q, self::refused($q), 'dns_amplification', $requestLen, $udp);
        }

        // A query: mirror / honeypot / sinkhole.
        if ($q->qtype === DnsMessage::TYPE_A) {
            [$ip, $event] = self::resolveA($q, $peerIp, $cfg);
            $answer = DnsMessage::encodeRr($q->qname, DnsMessage::TYPE_A, DnsMessage::CLASS_IN, 60, DnsMessage::rdataA($ip));
            $full = DnsMessage::encodeResponse($q, DnsMessage::RCODE_NOERROR, 1) . $answer;

            return self::clampUdp($q, $full, $event, $requestLen, $udp);
        }

        // Everything else (NS/SOA/AAAA/MX/…): a quiet NOERROR with no answer.
        return self::clampUdp($q, DnsMessage::encodeResponse($q, DnsMessage::RCODE_NOERROR, 0), 'dns_query', $requestLen, $udp);
    }

    /** @return array{0:string,1:string} [ip, event] */
    private static function resolveA(DnsQuery $q, string $peerIp, DnsConfig $cfg): array
    {
        if ($cfg->mode === DnsConfig::MODE_SINKHOLE) {
            if (isset($cfg->sinkhole[$q->qname])) {
                return [$cfg->sinkhole[$q->qname], 'dns_sinkhole'];
            }

            return [$peerIp, 'dns_mirror']; // non-bad names still get the mirror troll
        }
        if ($cfg->mode === DnsConfig::MODE_HONEYPOT) {
            return [$cfg->selfIp, 'dns_honeypot'];
        }

        return [$peerIp, 'dns_mirror']; // default: "uno reverse"
    }

    private static function chaos(DnsQuery $q, DnsConfig $cfg): string
    {
        $txt = match ($q->qname) {
            'version.bind' => $cfg->versionBind(),
            'hostname.bind' => $cfg->bindHostname,
            'id.server' => $cfg->serverId,
            default => $cfg->versionBind(),
        };
        $answer = DnsMessage::encodeRr($q->qname, DnsMessage::TYPE_TXT, DnsMessage::CLASS_CH, 0, DnsMessage::rdataTxt($txt));

        return DnsMessage::encodeResponse($q, DnsMessage::RCODE_NOERROR, 1) . $answer;
    }

    private static function axfrZone(DnsQuery $q, DnsConfig $cfg): string
    {
        $soaRdata = DnsMessage::encodeName('ns1.' . $cfg->zoneApex)
            . DnsMessage::encodeName('hostmaster.' . $cfg->zoneApex)
            . \pack('N', 2024010101) // serial
            . \pack('N', 3600) . \pack('N', 600) . \pack('N', 604800) . \pack('N', 300);
        $soa = DnsMessage::encodeRr($cfg->zoneApex, DnsMessage::TYPE_SOA, DnsMessage::CLASS_IN, 3600, $soaRdata);

        $records = $soa
            . DnsMessage::encodeRr($cfg->zoneApex, DnsMessage::TYPE_NS, DnsMessage::CLASS_IN, 3600, DnsMessage::encodeName('ns1.' . $cfg->zoneApex));
        $count = 2;
        foreach ($cfg->axfrZone as $name => $ip) {
            if ($count >= self::MAX_ZONE_RECORDS) {
                break;
            }
            $records .= DnsMessage::encodeRr($name, DnsMessage::TYPE_A, DnsMessage::CLASS_IN, 3600, DnsMessage::rdataA($ip));
            $count++;
        }
        $records .= $soa; // AXFR brackets the zone with a closing SOA
        $count++;

        return DnsMessage::encodeResponse($q, DnsMessage::RCODE_NOERROR, $count) . $records;
    }

    private static function refused(DnsQuery $q): string
    {
        return DnsMessage::encodeResponse($q, DnsMessage::RCODE_REFUSED, 0);
    }

    /**
     * Over UDP, if the full answer exceeds the request, downgrade to TC=1 (question echoed, zero answers);
     * if even that would exceed, the server's final clamp emits nothing. Over TCP, pass the full answer.
     *
     * @return array{bytes:string,event:string,reportable:bool}
     */
    private static function clampUdp(DnsQuery $q, string $full, string $event, int $requestLen, bool $udp): array
    {
        if (!$udp) {
            return ['bytes' => $full, 'event' => $event, 'reportable' => true];
        }
        $bytes = \strlen($full) > $requestLen
            ? DnsMessage::encodeResponse($q, DnsMessage::RCODE_NOERROR, 0, true) // TC=1 truncated
            : $full;

        return ['bytes' => $bytes, 'event' => $event, 'reportable' => false];
    }
}
