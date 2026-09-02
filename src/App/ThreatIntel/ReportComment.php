<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

/**
 * Builds the public comment attached to an outbound abuse report (FP-0247, Fix H).
 *
 * AbuseIPDB comments are PUBLIC. The raw material — a request path, a protocol payload, a captured
 * command — is attacker-controlled and routinely carries harvested third-party credentials, tokens,
 * emails, exploit blobs, an injected third-party hostname, or arbitrary bytes. Republishing any of
 * that verbatim would leak a victim's secrets and hand an attacker a channel to plant text in a
 * public record naming an innocent host. build() keeps the trusted, structured prefix (protocol,
 * port, event) intact and sanitises only the attacker-controlled detail: it drops a leading
 * scheme://host (so an absolute-URI request line cannot inject a third-party host even after the
 * Host header is dropped), redacts credential-bearing params and emails, collapses long base64/hex
 * blobs, strips non-printable bytes, and hard-truncates.
 */
final class ReportComment
{
    /**
     * Credential tokens. A param value is redacted when its NAME contains one of these as a
     * SEPARATOR-DELIMITED segment (bounded by start / `?` / `&` / `_` / `.` / `-` on the left, and by
     * `_` / `.` / `-` / `=` on the right). Delimiting avoids stripping benign params that merely embed
     * the letters — `author=` (the WordPress user-enumeration signal we WANT), `keyword=`, `monkey=`,
     * `turkey=`, `bypass=` — while still catching `access_token`, `refresh_token`, `client_secret`,
     * `session_id`, `x_api_key`, `user_password`, `X-Auth-Token` and a bare `?key=AIza…`.
     */
    private const CREDENTIAL_KEYS = 'password|passwd|pwd|pass|token|secret|session(?:id)?|apikey|api_key|auth|authorization|key';

    /**
     * @param string $prefix trusted, structured lead-in (e.g. "funnypot SSH honeypot, port 22: login")
     * @param string $detail attacker-controlled free text (a path, payload, or captured command)
     * @param int    $max    hard cap on the returned comment length
     */
    public static function build(string $prefix, string $detail, int $max = 300): string
    {
        $detail = self::sanitize($detail);
        $prefix = trim($prefix);
        $comment = $prefix === '' ? $detail : rtrim($prefix . ' ' . ltrim($detail));

        return substr($comment, 0, max(1, $max));
    }

    /** Sanitise attacker-controlled text so it is safe to publish. */
    private static function sanitize(string $s): string
    {
        // Drop a scheme://host authority anywhere it appears, keeping the path — an absolute-URI
        // request line (GET http://victim.example/x) must not name a third-party host in a public report.
        $s = (string) preg_replace('~[a-z][a-z0-9+.\-]*://[^\s/?\#]*~i', '', $s);
        // Also strip a leading protocol-relative authority (`//victim.example/admin`) — it carries no
        // scheme so the rule above misses it, yet nginx forwards `GET //host/path` verbatim, which
        // would name a third-party host in the public report. Keep the path.
        $s = (string) preg_replace('~(^|\s)//[^/?\#\s]*~', '$1', $s);
        // Redact credential-bearing params (case-insensitive, key=value). A plain `\b`-anchored key
        // list misses `_`-joined compounds (no word boundary sits between `_` and a letter), so
        // `access_token=` etc. would leak; a bare CONTAINS match over-redacts benign params like
        // `author=`/`keyword=`. The middle ground: the credential token must appear as a
        // SEPARATOR-DELIMITED segment of the name — bounded by start/`?`/`&`/`_`/`.`/`-` on the left
        // and continuing only through further `_`/`.`/`-` segments up to `=`. The whole name is kept
        // (forensic) while the value is dropped.
        $s = (string) preg_replace(
            '~((?:^|[?&_.\-])(?:' . self::CREDENTIAL_KEYS . ')(?:[_.\-][\w.\-]*)?)=([^&\s#]*)~i',
            '$1=[redacted]',
            $s
        );
        // Redact email addresses (victim PII).
        $s = (string) preg_replace('~[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}~', '[email]', $s);
        // Collapse long base64/hex runs (exfil/exploit blobs, encoded credentials) — the hex charset
        // is a subset of this class, so it covers both.
        $s = (string) preg_replace('~[A-Za-z0-9+/=]{48,}~', '[blob]', $s);
        // Strip control / non-printable bytes last.
        $s = (string) preg_replace('/[^\x20-\x7E]/', '?', $s);

        return trim($s);
    }
}
