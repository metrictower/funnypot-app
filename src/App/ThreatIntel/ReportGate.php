<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

/**
 * The single fail-closed decision point for whether a logged event may be reported to an external
 * intel destination (AbuseIPDB / our Threat Intel service).
 *
 * PARAMOUNT INVARIANT: funnypot must NEVER report a spoofed, unverified, or innocent source. A UDP
 * datagram's source address is trivially spoofable — a single forged datagram must never get an
 * innocent IP reported or blocklisted. Therefore the flag is fail-CLOSED: the ABSENCE of an explicit
 * `reportable` flag means "unverified", and unverified is never reported. Only an emitter that has
 * positively established the source (a TCP three-way handshake, or a verified UDP round-trip) may set
 * `reportable => true`. When in doubt, the report is dropped, never sent.
 *
 * demo/listen.php calls {@see maybeReport()} for every logged event; keeping the gate + enqueue here
 * (rather than inline in the listener closure) means there is exactly one wiring the tests can drive,
 * and a new emitter that forgets the flag silently reports nothing even if it ships.
 */
final class ReportGate
{
    /**
     * Fail-closed: report only when the emitter explicitly marked the event verified AND an IP is
     * present. Absence of the flag ⇒ unverified ⇒ never reported.
     *
     * @param array<string,mixed> $entry
     */
    public static function shouldReport(array $entry): bool
    {
        return ($entry['reportable'] ?? false) === true && ($entry['ip'] ?? '') !== '';
    }

    /**
     * The real gate + enqueue wiring called by demo/listen.php. Enqueues the event to whichever
     * reporters are armed, but ONLY when {@see shouldReport()} passes. Enqueue is a fast local write;
     * neither reporter touches the network here.
     *
     * @param array<string,mixed> $entry               the logged event (as built by a protocol server)
     * @param string              $defaultCategories    boot-time per-protocol category CSV
     */
    public static function maybeReport(
        array $entry,
        ?AbuseIpdb $abuse,
        ?ThreatIntelReporter $threatIntel,
        string $protocol,
        int $port,
        string $defaultCategories
    ): void {
        if (!self::shouldReport($entry) || ($abuse === null && $threatIntel === null)) {
            return;   // unverified / spoofable source, or no reporter armed: drop, never send
        }
        $ip = (string) $entry['ip'];
        $event = (string) ($entry['event'] ?? '');
        $data = (string) ($entry['path'] ?? $entry['body'] ?? '');
        $categories = (string) ($entry['categories'] ?? $defaultCategories);
        // FP-0247 (Fix H): the payload is attacker-controlled and the report is public — sanitise it
        // (drop third-party host, redact creds/emails/blobs, strip control bytes) before republishing.
        $comment = ReportComment::build(
            sprintf('funnypot %s honeypot, port %d: %s', strtoupper($protocol), $port, $event),
            $data
        );
        // FP-0247 (Fix F): forward small, non-PII request-shape signals + a protocol-tier confidence on
        // the Threat Intel report (the params existed but no call site ever passed them). The event only
        // reaches here after the fail-closed gate, i.e. the source is verified.
        $signals = ['protocol' => $protocol, 'event' => $event];
        $abuse?->enqueue($ip, $comment, $categories);
        $threatIntel?->enqueue($ip, $comment, $categories, $signals, 0.8);
    }
}
