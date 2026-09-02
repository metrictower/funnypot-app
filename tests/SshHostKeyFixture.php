<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\Ssh\HostKey\HostKeySet;

/**
 * A process-memoised {@see HostKeySet} for the SSH tests, so the RSA-3072 keygen (~0.5 s) runs once
 * per PHPUnit/paratest worker instead of once per test. The keys are persisted under a per-PID temp
 * directory and removed on shutdown.
 */
final class SshHostKeyFixture
{
    private static ?HostKeySet $set = null;
    private static string $dir = '';

    public static function set(): HostKeySet
    {
        if (self::$set === null) {
            self::$dir = sys_get_temp_dir() . '/fp-ssh-hk-' . getmypid();
            self::$set = HostKeySet::load(self::$dir . '/ssh_host_ed25519');
            register_shutdown_function(static function (): void {
                foreach (['ssh_host_ed25519', 'ssh_host_rsa_key', 'ssh_host_ecdsa_key'] as $f) {
                    @unlink(self::$dir . '/' . $f);
                }
                @rmdir(self::$dir);
            });
        }

        return self::$set;
    }
}
