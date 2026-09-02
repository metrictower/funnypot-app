<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\Cipher\PacketCipher;
use Funnypot\Protocol\Ssh\HostKey\HostKeySet;
use Funnypot\Protocol\Ssh\Kex\KexAlgorithm;
use Funnypot\Protocol\Ssh\Kex\KexSuite;
use Funnypot\Protocol\Ssh\Reader;
use Funnypot\Protocol\Ssh\SshConnection;
use Funnypot\Protocol\Ssh\SshProfile;
use Funnypot\Protocol\Ssh\Transport;
use Funnypot\Shell\Host\HostIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0291 §4.1–4.3 — the banner-keyed profile: byte/order-exact KEXINIT and its hasshServer from the
 * actually-served bytes, banner↔profile coherence over the identity seeds, and the advertise ⇒
 * implement audit (every served name resolves to a live implementation). The served-bytes pin here
 * tracks the current commit; it is 04e7711c through the refactor commit, 557eee0f at the marker-only
 * commit, and 779664e6 once the Stage-1 lists flip.
 */
final class SshProfileTest extends TestCase
{
    private const BANNERS = [
        'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
        'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3',
        'SSH-2.0-OpenSSH_8.7',
        'SSH-2.0-OpenSSH_8.9p1',
    ];

    /** Read the KEXINIT the server actually serves for $banner, as a Reader positioned after byte+cookie. */
    private function servedKexInit(string $banner): Reader
    {
        $server = new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(1), static function (): void {
        }, $banner, 0);
        $server->onConnect();
        $server->takeOut();                          // drain the banner line
        $server->feed("SSH-2.0-TestClient_1.0\r\n"); // KEXINIT follows the client ident line (FP-0290)
        $buffer = $server->takeOut();
        $kexInit = (new Transport())->next($buffer);
        self::assertNotNull($kexInit);
        self::assertSame('', $buffer, 'exactly the KEXINIT, nothing trailing');
        $r = new Reader($kexInit);
        self::assertSame(20, $r->byte(), 'SSH_MSG_KEXINIT');
        $r->uint32();
        $r->uint32();
        $r->uint32();
        $r->uint32(); // 16-byte cookie
        return $r;
    }

    public function test_served_kexinit_is_byte_and_order_exact_with_hassh(): void
    {
        // The current-commit served shape (updated with each stage of the flip). Written as literals
        // here, never read from the profile, so a profile edit must satisfy this pin explicitly.
        $kex = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'kex-strict-s-v00@openssh.com'];
        $hostKeys = ['ssh-ed25519'];
        $ciphers = ['aes256-ctr'];
        $macs = ['hmac-sha2-256'];
        $comp = ['none'];
        $hassh = '557eee0f76ba1b566aa8960f3b5434c1'; // commit 4 marker-only; 779664e6 after the full flip

        foreach (self::BANNERS as $banner) {
            $r = $this->servedKexInit($banner);
            self::assertSame($kex, $r->nameList(), "{$banner}: kex_algorithms");
            self::assertSame($hostKeys, $r->nameList(), "{$banner}: host keys");
            self::assertSame($ciphers, $r->nameList(), "{$banner}: enc c2s");
            $encS2C = $ciphers;
            self::assertSame($encS2C, $r->nameList(), "{$banner}: enc s2c");
            self::assertSame($macs, $r->nameList(), "{$banner}: mac c2s");
            $macS2C = $macs;
            self::assertSame($macS2C, $r->nameList(), "{$banner}: mac s2c");
            self::assertSame($comp, $r->nameList(), "{$banner}: comp c2s");
            $compS2C = $comp;
            self::assertSame($compS2C, $r->nameList(), "{$banner}: comp s2c");
            self::assertSame([], $r->nameList(), "{$banner}: languages c2s");
            self::assertSame([], $r->nameList(), "{$banner}: languages s2c");
            self::assertFalse($r->bool(), "{$banner}: first_kex_packet_follows");
            self::assertSame(0, $r->uint32(), "{$banner}: reserved");

            // hasshServer over the SERVED s2c lists == the value; the profile agrees; c2s equals it.
            $servedHassh = md5(implode(',', $kex) . ';' . implode(',', $encS2C) . ';' . implode(',', $macS2C) . ';' . implode(',', $compS2C));
            self::assertSame($hassh, $servedHassh, "{$banner}: hasshServer from served bytes");
            self::assertSame($hassh, SshProfile::forBanner($banner)->hasshServer(), "{$banner}: profile hasshServer");

            // Unseen-hash sentinels: dropping the umac names (ab7e2ad8) or zlib (056287fe) would
            // recreate an impossible-shape hash, and sntrup-first (a65c3b91) is the 9.2/Profile B
            // target — none must ever be the served shape in Stage 1 (mirror of D1/§2.6/M3).
            self::assertNotSame('ab7e2ad84e97884032ffe1ac8be581c3', $servedHassh, 'umac names must not be dropped');
            self::assertNotSame('056287fea4f95edbc2d6c51adb01c959', $servedHassh, 'zlib must not be dropped');
            self::assertNotSame('a65c3b91f743d3f246e72172e77288f1', $servedHassh, 'sntrup761 must not be inserted before FP-0292');
        }
    }

    public function test_cookie_is_random_but_the_name_lists_are_deterministic(): void
    {
        $a = SshProfile::forBanner('SSH-2.0-OpenSSH_8.9p1')->kexInit(random_bytes(16));
        $b = SshProfile::forBanner('SSH-2.0-OpenSSH_8.9p1')->kexInit(random_bytes(16));
        self::assertNotSame(substr($a, 1, 16), substr($b, 1, 16), 'cookies differ');
        self::assertSame(substr($a, 17), substr($b, 17), 'everything after the cookie is deterministic');
    }

    public function test_forbanner_throws_on_an_unmodelled_banner(): void
    {
        foreach (['', 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3', 'SSH-2.0-dropbear_2022.83', 'SSH-2.0-OpenSSH_8.9p10'] as $banner) {
            try {
                SshProfile::forBanner($banner);
                self::fail("expected a throw for '{$banner}'");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('no profile', $e->getMessage());
            }
        }
        // SshConnection construction throws too — never a silent fallback list.
        $this->expectException(\InvalidArgumentException::class);
        new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(1), static function (): void {
        }, 'SSH-2.0-OpenSSH_8.4p1', 0);
    }

    public function test_banner_to_profile_coherence_over_identity_seeds(): void
    {
        $seen = ['ubuntu' => false, 'debian' => false, 'other' => false];
        for ($s = 0; $s < 256; $s++) {
            $identity = HostIdentity::fromSeed($s);
            $banner = $identity->sshBanner();
            $profile = SshProfile::forBanner($banner); // never throws for a real persona banner
            self::assertSame(0, strpos($banner, $profile->bannerPrefix()), 'the profile prefix is a prefix of the banner');
            $id = $identity->osReleaseId();
            if ($id === 'ubuntu') {
                self::assertSame(SshProfile::OPENSSH_8_9P1_UBUNTU, $profile->bannerPrefix());
                $seen['ubuntu'] = true;
            } elseif ($id === 'debian') {
                self::assertSame(SshProfile::OPENSSH_9_2P1_DEBIAN, $profile->bannerPrefix());
                $seen['debian'] = true;
            } else {
                self::assertSame(SshProfile::OPENSSH_8_7_EL9, $profile->bannerPrefix());
                $seen['other'] = true;
            }
        }
        self::assertSame(['ubuntu' => true, 'debian' => true, 'other' => true], $seen, 'all three profiles are reached');
    }

    public function test_ext_info_shape_per_profile(): void
    {
        $a = SshProfile::forBanner('SSH-2.0-OpenSSH_8.9p1')->extInfo();
        self::assertSame(['server-sig-algs', 'publickey-hostbound@openssh.com'], array_keys($a), 'A: nr=2');
        self::assertSame('0', $a['publickey-hostbound@openssh.com']);
        self::assertStringContainsString('webauthn-sk-ecdsa-sha2-nistp256@openssh.com', $a['server-sig-algs']);

        $b = SshProfile::forBanner('SSH-2.0-OpenSSH_9.2p1')->extInfo();
        self::assertSame(['server-sig-algs', 'publickey-hostbound@openssh.com'], array_keys($b), 'B: nr=2');

        $c = SshProfile::forBanner('SSH-2.0-OpenSSH_8.7')->extInfo();
        self::assertSame(['server-sig-algs'], array_keys($c), 'C (el9 8.7): nr=1, no hostbound');
        self::assertStringNotContainsString('webauthn', $c['server-sig-algs'], 'C: no webauthn-sk (introduced in 8.9)');
    }

    /**
     * The advertise ⇒ implement audit (§4.3): every served name of every profile resolves to a live
     * implementation, and any marker is kex-strict-s in last position. Stage-independent — it audits
     * whatever the profiles currently serve, so it holds at every commit of the flip.
     */
    public function test_every_served_name_resolves_to_an_implementation(): void
    {
        $hostKeys = SshHostKeyFixture::set();
        foreach (self::BANNERS as $banner) {
            $p = SshProfile::forBanner($banner);

            $markerCount = 0;
            $lastIndex = count($p->kex()) - 1;
            foreach ($p->kex() as $i => $name) {
                if (KexSuite::isMarker($name)) {
                    $markerCount++;
                    self::assertSame(KexSuite::KEX_STRICT_S, $name, "{$banner}: the only marker is kex-strict-s");
                    self::assertSame($lastIndex, $i, "{$banner}: the marker is last");
                    continue;
                }
                self::assertContains($name, KexSuite::NAMES, "{$banner}: {$name} is a real kex name");
                $kex = KexSuite::create($name, 'vc', 'vs', 'ic', 'is', $hostKeys->forAlgorithm('ssh-ed25519'));
                self::assertInstanceOf(KexAlgorithm::class, $kex, "{$banner}: {$name} builds a KexAlgorithm");
            }
            self::assertLessThanOrEqual(1, $markerCount, "{$banner}: at most one marker");

            foreach ($p->hostKeys() as $name) {
                self::assertContains($name, HostKeySet::ALGORITHMS, "{$banner}: {$name} is a known host-key name");
                self::assertNotNull($hostKeys->forAlgorithm($name), "{$banner}: {$name} resolves to a signer");
            }

            foreach ($p->ciphers() as $cipher) {
                $key = random_bytes(CipherSuite::keyLen($cipher));
                $ivLen = CipherSuite::ivLen($cipher);
                $iv = $ivLen > 0 ? random_bytes($ivLen) : '';
                self::assertGreaterThan(0, CipherSuite::blockSize($cipher));
                self::assertInstanceOf(PacketCipher::class, CipherSuite::build($cipher, 'hmac-sha2-256', $key, $iv, random_bytes(32)), "{$banner}: cipher {$cipher} builds");
            }

            foreach ($p->macs() as $mac) {
                $keyLen = CipherSuite::macKeyLen($mac);
                self::assertGreaterThan(0, $keyLen);
                self::assertGreaterThan(0, CipherSuite::macTagLen($mac));
                self::assertInstanceOf(PacketCipher::class, CipherSuite::build('aes256-ctr', $mac, random_bytes(32), random_bytes(16), random_bytes($keyLen)), "{$banner}: mac {$mac} builds");
            }

            foreach ($p->compression() as $comp) {
                self::assertContains($comp, ['none', 'zlib@openssh.com'], "{$banner}: compression {$comp}");
                if ($comp === 'zlib@openssh.com') {
                    self::assertTrue(method_exists(Transport::class, 'enableSendCompression'));
                }
            }
        }
    }
}
