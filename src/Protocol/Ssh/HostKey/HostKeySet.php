<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\HostKey;

/**
 * The set of host keys the server offers — one per signature algorithm a stock 22.04 sshd advertises
 * (rsa-sha2-512/256, ecdsa-sha2-nistp256, ssh-ed25519). {@see forAlgorithm()} maps a negotiated
 * host-key name to the signer; an unknown name throws, so "advertise ⇒ implement" holds at selection
 * time. This ticket does not advertise the new names (the served list stays ssh-ed25519 only); the
 * set sits built and signature-verified for the flip ticket.
 *
 * {@see load()} is the eager, once-per-deploy I/O entry point: it reads (or first-generates and
 * persists) all three keys before the listener binds, so RSA-3072's ~0.5 s keygen never lands in the
 * select loop. FUNNYPOT_SSH_HOSTKEY keeps its meaning — the path of the ed25519 key file — and the
 * RSA/ECDSA keys live beside it (ssh_host_rsa_key / ssh_host_ecdsa_key), so a deploy with an existing
 * ed25519 key keeps that fingerprint while gaining the siblings on first start.
 */
final class HostKeySet
{
    /** The signature names FP-0291 will advertise, in a stock 22.04 sshd's order. */
    public const ALGORITHMS = ['rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519'];

    public function __construct(
        private Ed25519 $ed25519,
        private Rsa $rsa,
        private Ecdsa $ecdsa
    ) {
    }

    /** The signer for a negotiated host-key name; throws on an unknown/unoffered name. */
    public function forAlgorithm(string $name): HostKeyAlgorithm
    {
        return match ($name) {
            'ssh-ed25519' => $this->ed25519,
            'ecdsa-sha2-nistp256' => $this->ecdsa,
            'rsa-sha2-512' => $this->rsa->withAlgorithm('rsa-sha2-512'),
            'rsa-sha2-256' => $this->rsa->withAlgorithm('rsa-sha2-256'),
            default => throw new \InvalidArgumentException("ssh: unknown host-key algorithm {$name}"),
        };
    }

    /**
     * Eagerly load all three keys, reading each from disk or generating + persisting it on first
     * use. $ed25519Path is the ed25519 file (FUNNYPOT_SSH_HOSTKEY); the RSA/ECDSA keys are siblings
     * in the same directory.
     */
    public static function load(string $ed25519Path): self
    {
        $dir = dirname($ed25519Path);
        $failed = false;

        $ed = self::loadOrGenerate(
            $ed25519Path,
            static fn (string $raw): ?Ed25519 => Ed25519::fromRaw($raw),
            static fn (): Ed25519 => Ed25519::generate(),
            static fn (Ed25519 $k): string => $k->raw(),
            $failed
        );
        $rsa = self::loadOrGenerate(
            $dir . '/ssh_host_rsa_key',
            static fn (string $pem): ?Rsa => Rsa::fromPem($pem),
            static fn (): Rsa => Rsa::generate(),
            static fn (Rsa $k): string => $k->pem(),
            $failed
        );
        $ecdsa = self::loadOrGenerate(
            $dir . '/ssh_host_ecdsa_key',
            static fn (string $pem): ?Ecdsa => Ecdsa::fromPem($pem),
            static fn (): Ecdsa => Ecdsa::generate(),
            static fn (Ecdsa $k): string => $k->pem(),
            $failed
        );

        if ($failed) {
            // Never silent: a host key that cannot be persisted rotates on restart (a tell) and may
            // differ between processes. Logged once (not per connection), matching HostSecret.
            error_log('funnypot: SSH host key(s) could not be persisted to ' . $dir
                . ' — set FUNNYPOT_SSH_HOSTKEY or fix the data-volume permissions');
        }

        return new self($ed, $rsa, $ecdsa);
    }

    /** All three freshly generated with no I/O — for tests. */
    public static function generate(): self
    {
        return new self(Ed25519::generate(), Rsa::generate(), Ecdsa::generate());
    }

    /**
     * Read $path and reconstruct a key from it; on a missing/corrupt file generate a fresh key and
     * persist it, flagging $failed when the write does not land (so the caller can log once).
     *
     * @template T of HostKeyAlgorithm
     * @param callable(string):?T $from      reconstruct from the raw file body, null when not valid
     * @param callable():T        $generate  a fresh key
     * @param callable(T):string  $serialize the on-disk body of a key
     * @return T
     */
    private static function loadOrGenerate(string $path, callable $from, callable $generate, callable $serialize, bool &$failed)
    {
        $raw = @file_get_contents($path);
        if ($raw !== false) {
            $key = $from($raw);
            if ($key !== null) {
                return $key;
            }
        }

        $key = $generate();
        @mkdir(dirname($path), 0700, true);
        if (@file_put_contents($path, $serialize($key)) !== false) {
            @chmod($path, 0600);
        } else {
            $failed = true;
        }

        return $key;
    }
}
