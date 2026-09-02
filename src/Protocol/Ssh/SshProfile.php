<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

use Funnypot\Protocol\Ssh\Kex\KexSuite;

/**
 * The banner-keyed SSH algorithm profile: it turns the server's identification string into the exact
 * KEXINIT name-lists and SSH_MSG_EXT_INFO that persona serves, so the banner and the KEXINIT can
 * never disagree per deploy. {@see forBanner()} is a total function with a throw — a persona whose
 * banner is not modelled must never ship an un-modelled KEXINIT (HostIdentity emits exactly the three
 * banners below). The served lists are a pure function of the profile; the profile is a pure function
 * of the banner; nothing here reads an attacker byte, clock, env or key.
 *
 * Three profiles (the three banners HostIdentity emits): A = 8.9p1 (Ubuntu 22.04), B = 9.2p1
 * (Debian 12), C = 8.7 (el9 family). In this refactor commit all three serve the *current* single-
 * choice lists byte-for-byte (hasshServer 04e7711c) — the plumbing moves, the served bytes do not.
 * The kex-strict-s marker (commit 4) and the full Stage-1 lists (commit 5) then flip these arrays;
 * FP-0292 diverges B (sntrup761 first) and FP-0293 diverges C (el9 cbc/order). Each profile's target
 * list is spelled in the comment above its entry so those later flips are a literal edit:
 *
 *   Profile A target (8.9p1, FP-0292 → 41ff3ecd): curve25519-sha256, curve25519-sha256@libssh.org,
 *     ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521,
 *     sntrup761x25519-sha512@openssh.com,           ← AFTER ecdh-nistp521 (8.9 myproposal.h order;
 *     diffie-hellman-group-exchange-sha256,            sntrup moved to FIRST only in 9.0 — placing it
 *     diffie-hellman-group16-sha512, group18-sha512,   first yields a65c3b91, the 9.2/Profile B shape)
 *     diffie-hellman-group14-sha256, kex-strict-s-v00@openssh.com
 *   Profile B target (9.2p1, → a65c3b91): sntrup761x25519-sha512@openssh.com FIRST, then the same.
 *   Profile C target (8.7 el9, FP-0293): adds aes256-cbc/aes128-cbc and the el9 crypto-policies order.
 *
 * In Stage 1 all three serve Profile A's shape (779664e6, a real OpenSSH 8.2/8.4 hasshServer) — a
 * banner-version skew that shrinks with FP-0292/0293 and is the accepted Stage-1 trade.
 */
final class SshProfile
{
    public const OPENSSH_8_9P1_UBUNTU = 'SSH-2.0-OpenSSH_8.9p1';   // Profile A (HostIdentity 8.9p1 Ubuntu)
    public const OPENSSH_9_2P1_DEBIAN = 'SSH-2.0-OpenSSH_9.2p1';   // Profile B (HostIdentity 9.2p1 Debian)
    public const OPENSSH_8_7_EL9      = 'SSH-2.0-OpenSSH_8.7';     // Profile C (HostIdentity 8.7 el9)

    // The 8.9p1 sshkey_alg_list(0,1,1) server-sig-algs (ENABLE_SK, no WITH_XMSS) — the Ubuntu build.
    private const SERVER_SIG_ALGS_89 = 'ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com';
    // el9's 8.7 has no webauthn-sk (introduced in 8.9) and nr=1 (no publickey-hostbound, also 8.9).
    private const SERVER_SIG_ALGS_87 = 'ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com';

    // Stage-1 (this commit): every profile serves the current single-choice lists byte-for-byte.
    private const KEX = ['curve25519-sha256', 'curve25519-sha256@libssh.org'];
    private const HOSTKEYS = ['ssh-ed25519'];
    private const CIPHERS = ['aes256-ctr'];
    private const MACS = ['hmac-sha2-256'];
    private const COMPRESSION = ['none'];

    /** @var array<string,string> */
    private array $extInfo;

    /**
     * @param string[]              $kex
     * @param string[]              $hostKeys
     * @param string[]              $ciphers
     * @param string[]              $macs
     * @param string[]              $compression
     * @param array<string,string>  $extInfo
     */
    private function __construct(
        private string $bannerPrefix,
        private array $kex,
        private array $hostKeys,
        private array $ciphers,
        private array $macs,
        private array $compression,
        array $extInfo
    ) {
        $this->extInfo = $extInfo;
    }

    /**
     * Resolve the profile for a full identification string by longest-prefix match, the version
     * suffix ("Ubuntu-3ubuntu0.10" etc.) irrelevant. The prefix must be followed by end-of-string,
     * a space or a CR so "…_8.9p1" never matches a hypothetical "…_8.9p10". Throws on anything not
     * modelled — a persona must never ship an un-modelled KEXINIT.
     */
    public static function forBanner(string $banner): self
    {
        $entries = [
            self::OPENSSH_8_9P1_UBUNTU => [self::SERVER_SIG_ALGS_89, true],   // A: nr=2 (hostbound)
            self::OPENSSH_9_2P1_DEBIAN => [self::SERVER_SIG_ALGS_89, true],   // B: nr=2 (9.2 has hostbound)
            self::OPENSSH_8_7_EL9      => [self::SERVER_SIG_ALGS_87, false],  // C: nr=1 (no hostbound)
        ];
        $best = null;
        $bestLen = -1;
        foreach ($entries as $prefix => $ext) {
            $len = strlen($prefix);
            if (strncmp($banner, $prefix, $len) !== 0) {
                continue;
            }
            if (strlen($banner) !== $len) {
                $next = $banner[$len];
                if ($next !== ' ' && $next !== "\r") {
                    continue;
                }
            }
            if ($len > $bestLen) {
                $best = [$prefix, $ext];
                $bestLen = $len;
            }
        }
        if ($best === null) {
            throw new \InvalidArgumentException("ssh: no profile for banner '{$banner}'");
        }
        [$prefix, $ext] = $best;
        [$serverSigAlgs, $hostbound] = $ext;

        $extInfo = ['server-sig-algs' => $serverSigAlgs];
        if ($hostbound) {
            $extInfo['publickey-hostbound@openssh.com'] = '0';
        }

        return new self($prefix, self::KEX, self::HOSTKEYS, self::CIPHERS, self::MACS, self::COMPRESSION, $extInfo);
    }

    public function bannerPrefix(): string
    {
        return $this->bannerPrefix;
    }

    /** @return string[] */
    public function kex(): array
    {
        return $this->kex;
    }

    /** @return string[] */
    public function hostKeys(): array
    {
        return $this->hostKeys;
    }

    /** @return string[] */
    public function ciphers(): array
    {
        return $this->ciphers;
    }

    /** @return string[] */
    public function macs(): array
    {
        return $this->macs;
    }

    /** @return string[] */
    public function compression(): array
    {
        return $this->compression;
    }

    /** @return array<string,string> ordered extension-name => value for SSH_MSG_EXT_INFO */
    public function extInfo(): array
    {
        return $this->extInfo;
    }

    /** THE two-sided strict-kex gate FP-0290 reads: does our served kex list carry kex-strict-s? */
    public function advertisesStrictKex(): bool
    {
        return in_array(KexSuite::KEX_STRICT_S, $this->kex, true);
    }

    /** The SSH_MSG_KEXINIT payload: byte 20 ‖ cookie(16) ‖ the ten name-lists ‖ false ‖ uint32 0. */
    public function kexInit(string $cookie): string
    {
        return (new Buf())
            ->byte(20)
            ->raw($cookie)
            ->nameList($this->kex)
            ->nameList($this->hostKeys)
            ->nameList($this->ciphers)       // encryption client->server
            ->nameList($this->ciphers)       // encryption server->client
            ->nameList($this->macs)          // mac client->server
            ->nameList($this->macs)          // mac server->client
            ->nameList($this->compression)   // compression client->server
            ->nameList($this->compression)   // compression server->client
            ->nameList([])                   // languages client->server
            ->nameList([])                   // languages server->client
            ->bool(false)                    // first_kex_packet_follows
            ->uint32(0)                      // reserved
            ->get();
    }

    /** hasshServer = md5(kex;enc_s2c;mac_s2c;comp_s2c) — the profile is symmetric, so c2s is equal. */
    public function hasshServer(): string
    {
        return md5(
            implode(',', $this->kex) . ';'
            . implode(',', $this->ciphers) . ';'
            . implode(',', $this->macs) . ';'
            . implode(',', $this->compression)
        );
    }
}
