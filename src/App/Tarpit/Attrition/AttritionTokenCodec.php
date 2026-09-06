<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

use SodiumException;

/**
 * The journey-specific token codec (FP-0272 §5). It signs and verifies the four kind-separated 117-byte
 * handles the attrition journey uses, derives every child handle from its parent under a distinct fixed
 * domain, and derives the install-local 128-bit stored ids the state store keys on. There is deliberately
 * no arbitrary kind/label signer: a caller-chosen domain would let one handle forge another.
 *
 * Every handle is exactly 117 ASCII bytes:
 *   at1.<kind>.<issued10>.<expires10>.<subject22>.<nonce22>.<mac43>
 * kind ∈ e|j|m|a; times are canonical 10-digit UTC epoch seconds; subject/nonce are unpadded base64url of
 * 16 bytes each; mac is unpadded base64url of the full 32 HMAC-SHA256 bytes. Verification checks exact
 * length/grammar and canonical decoding BEFORE any crypto, then kind, a constant-time MAC compare, and the
 * bounded time window. It touches no storage and returns one immutable {@see AttritionHandle} or null.
 *
 * The subject is a keyed 15-minute partition of the already-resolved peer — a safety/quota scope, never
 * identity: it is not stored raw, does not decide eligibility, and is not re-checked against the peer on
 * later bearer use. A child handle inherits its parent's subject, issue and expiry, so following the
 * journey never extends a token's lifetime.
 */
final class AttritionTokenCodec
{
    public const VERSION = 'at1';
    public const TOKEN_BYTES = 117;
    public const MIN_LIFETIME_S = 3600;
    public const MAX_LIFETIME_S = 21600;
    public const CLOCK_SKEW_S = 30;
    public const ISSUE_BUCKET_S = 900;

    private const GRAMMAR = '/\Aat1\.(e|j|m|a)\.([1-9][0-9]{9})\.([1-9][0-9]{9})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})\z/';

    private const HANDLE_DOMAIN = 'funnypot-attrition-handle/v1';
    private const SUBJECT_DOMAIN = 'attrition-journey-subject/v1';
    private const ENTRY_NONCE_DOMAIN = 'attrition-entry-nonce/v1';
    private const JOB_NONCE_DOMAIN = 'attrition-job-nonce/v1';
    private const MANIFEST_FIRST_DOMAIN = 'attrition-manifest-first/v1';
    private const MANIFEST_NEXT_DOMAIN = 'attrition-manifest-next/v1';
    private const ARTIFACT_NONCE_DOMAIN = 'attrition-artifact-nonce/v1';

    private const STATE_JOURNEY_DOMAIN = 'attrition-state-journey/v1';
    private const STATE_GENERATION_DOMAIN = 'attrition-state-generation/v1';

    /** @var array<string,string> kind → its stored-id HMAC domain over the whole token bytes */
    private const STATE_ID_DOMAIN = [
        AttritionHandle::KIND_ENTRY => 'attrition-state-entry/v1',
        AttritionHandle::KIND_JOB => 'attrition-state-job/v1',
        AttritionHandle::KIND_MANIFEST => 'attrition-state-manifest/v1',
        AttritionHandle::KIND_ARTIFACT => 'attrition-state-artifact/v1',
    ];

    public function __construct(private string $key)
    {
    }

    /**
     * Mint an entry handle for a prevalidated canonical labyrinth route and the already-resolved peer,
     * or null if the peer is not a valid IP. The issue/expiry are pinned to the 15-minute bucket start
     * so the same peer + route within one bucket yields a byte-identical token; expiry is bucket + ttl,
     * clamped to the token lifetime window.
     */
    public function issueEntry(string $route, string $peer, int $now, int $ttlS): ?string
    {
        $peerBytes = self::canonicalPeer($peer);
        if ($peerBytes === null) {
            return null;
        }
        $bucket = intdiv($now, self::ISSUE_BUCKET_S) * self::ISSUE_BUCKET_S;
        $ttl = max(self::MIN_LIFETIME_S, min(self::MAX_LIFETIME_S, $ttlS));
        $subject = $this->derive16(self::SUBJECT_DOMAIN, $peerBytes, (string) $bucket);
        $nonce = $this->derive16(self::ENTRY_NONCE_DOMAIN, $subject, $route);

        return $this->encode(AttritionHandle::KIND_ENTRY, $bucket, $bucket + $ttl, $subject, $nonce);
    }

    public function deriveJob(AttritionHandle $entry): string
    {
        $nonce = $this->derive16(self::JOB_NONCE_DOMAIN, $entry->subject, $entry->nonce);

        return $this->encode(AttritionHandle::KIND_JOB, $entry->issuedAt, $entry->expiresAt, $entry->subject, $nonce);
    }

    public function deriveFirstManifest(AttritionHandle $job): string
    {
        $nonce = $this->derive16(self::MANIFEST_FIRST_DOMAIN, $job->subject, $job->nonce);

        return $this->encode(AttritionHandle::KIND_MANIFEST, $job->issuedAt, $job->expiresAt, $job->subject, $nonce);
    }

    public function deriveNextManifest(AttritionHandle $manifest, int $nextGeneration): string
    {
        $nonce = $this->derive16(self::MANIFEST_NEXT_DOMAIN, $manifest->subject, $manifest->nonce, (string) $nextGeneration);

        return $this->encode(AttritionHandle::KIND_MANIFEST, $manifest->issuedAt, $manifest->expiresAt, $manifest->subject, $nonce);
    }

    public function deriveArtifact(AttritionHandle $manifest, int $generation): string
    {
        $nonce = $this->derive16(self::ARTIFACT_NONCE_DOMAIN, $manifest->subject, $manifest->nonce, (string) $generation);

        return $this->encode(AttritionHandle::KIND_ARTIFACT, $manifest->issuedAt, $manifest->expiresAt, $manifest->subject, $nonce);
    }

    /**
     * Verify one token against exactly $expectedKind at $now, returning the typed handle or null. Order:
     * length, grammar, canonical base64url decode, kind, constant-time MAC, then the time window. Any
     * failure returns null before storage is ever touched.
     */
    public function verifyExpectedKind(string $token, string $expectedKind, int $now): ?AttritionHandle
    {
        if (strlen($token) !== self::TOKEN_BYTES || preg_match(self::GRAMMAR, $token, $m) !== 1) {
            return null;
        }
        $kind = $m[1];
        if (!hash_equals($expectedKind, $kind)) {
            return null;
        }
        $subject = self::decodeCanonical($m[4], 16);
        $nonce = self::decodeCanonical($m[5], 16);
        $mac = self::decodeCanonical($m[6], 32);
        if ($subject === null || $nonce === null || $mac === null) {
            return null;
        }
        $issued = (int) $m[2];
        $expires = (int) $m[3];
        if (!hash_equals($this->mac($kind, $issued, $expires, $subject, $nonce), $mac)) {
            return null;
        }
        if ($issued > $now + self::CLOCK_SKEW_S || $expires <= $now) {
            return null;
        }
        $lifetime = $expires - $issued;
        if ($lifetime < self::MIN_LIFETIME_S || $lifetime > self::MAX_LIFETIME_S) {
            return null;
        }

        return new AttritionHandle($kind, $issued, $expires, $subject, $nonce);
    }

    /** The journey partition id: keyed over the subject + the entry issue bucket (its issued epoch). */
    public function journeyId(AttritionHandle $h): string
    {
        return bin2hex($this->derive16(self::STATE_JOURNEY_DOMAIN, $h->subject, (string) $h->issuedAt));
    }

    /** The 32-hex stored id for a token, under its kind's own state domain over the whole token bytes. */
    public function storedId(string $token, string $kind): string
    {
        $domain = self::STATE_ID_DOMAIN[$kind] ?? '';

        return bin2hex(substr(hash_hmac('sha256', $domain . "\0" . $token, $this->key, true), 0, 16));
    }

    /**
     * The 32-hex generation-row (PRIMARY KEY) surrogate. It MUST be unique per (job, generation), not
     * just per (subject, generation): a peer earns one subject + issue bucket for the whole 15-minute
     * window, so two canonical pages requested by the same peer mint two distinct jobs in one journey
     * that share subject and issued_at. Keying on the manifest handle's nonce — which inherits the
     * job/route lineage the same way manifest_id/artifact_id do — makes the id job-unique, so a second
     * job's generation commit does not collide with the first's on the generation_id PRIMARY KEY.
     */
    public function generationId(AttritionHandle $h, int $generation): string
    {
        return bin2hex($this->derive16(self::STATE_GENERATION_DOMAIN, $h->subject, $h->nonce, (string) $generation));
    }

    private function encode(string $kind, int $issued, int $expires, string $subject, string $nonce): string
    {
        $mac = $this->mac($kind, $issued, $expires, $subject, $nonce);

        return implode('.', [
            self::VERSION,
            $kind,
            (string) $issued,
            (string) $expires,
            self::b64($subject),
            self::b64($nonce),
            self::b64($mac),
        ]);
    }

    private function mac(string $kind, int $issued, int $expires, string $subject, string $nonce): string
    {
        $input = self::HANDLE_DOMAIN . "\0" . $kind . "\0" . $issued . "\0" . $expires . "\0" . $subject . "\0" . $nonce;

        return hash_hmac('sha256', $input, $this->key, true);
    }

    /** First 16 HMAC-SHA256 bytes under the install key for one fixed domain + NUL-joined parts. */
    private function derive16(string $domain, string ...$parts): string
    {
        return substr(hash_hmac('sha256', $domain . "\0" . implode("\0", $parts), $this->key, true), 0, 16);
    }

    private static function b64(string $raw): string
    {
        return sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /** Decode $encoded and require it to be the canonical unpadded base64url of exactly $bytes bytes. */
    private static function decodeCanonical(string $encoded, int $bytes): ?string
    {
        try {
            $raw = sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (SodiumException $e) {
            return null;
        }
        if (strlen($raw) !== $bytes || !hash_equals($encoded, self::b64($raw))) {
            return null;
        }

        return $raw;
    }

    /** Canonicalize an IP to one family byte + its packed bytes; IPv4-mapped IPv6 folds to IPv4. Null if not an IP. */
    private static function canonicalPeer(string $ip): ?string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        if (strlen($packed) === 16 && substr($packed, 0, 10) === str_repeat("\0", 10) && substr($packed, 10, 2) === "\xff\xff") {
            $packed = substr($packed, 12, 4);
        }

        return (strlen($packed) === 4 ? "\x04" : "\x06") . $packed;
    }
}
