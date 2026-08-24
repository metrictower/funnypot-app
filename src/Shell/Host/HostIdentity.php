<?php

declare(strict_types=1);

namespace Funnypot\Shell\Host;

use Funnypot\App\Render\Fake\FrozenClock;

/**
 * The shell host's own identity — distro + kernel + hostname — deterministic per identity seed. The SSH/
 * telnet box is a distinct machine from the office admin panel, so this owns its own (real) distro strings
 * and a role-flavored hostname, all x86_64 (matching the ServerProfile hardware HostFacts pairs it with).
 *
 * Distro rows are REAL uname/os-release strings (kernel release, UTS build-string, distro-correct gcc, and
 * the distro's arch-suffix form — Debian's is the short "x86_64 GNU/Linux", others the triple). The UTS
 * build DATE renders from FrozenClock (a plausible past instant, never future). Hostname derives via
 * crc32(seed) sliced into role/style/env/region/seq arrays (operator's scheme) — so hostname == uname
 * nodename == /etc/hostname for a given seed, every render.
 */
final class HostIdentity
{
    /**
     * Real, x86_64 distro rows (from gathered uname -a / os-release strings). {DATE} in uts is filled
     * from the frozen clock. fam drives /etc/passwd+shadow shape (debian vs rhel).
     *
     * @var array<int,array{name:string,version:string,id:string,vid:string,pretty:string,kernel:string,uts:string,gcc:string,arch:string,fam:string}>
     */
    private const DISTROS = [
        ['name' => 'Ubuntu', 'version' => '22.04.5 LTS (Jammy Jellyfish)', 'id' => 'ubuntu', 'vid' => '22.04',
            'pretty' => 'Ubuntu 22.04.5 LTS', 'kernel' => '5.15.0-186-generic', 'uts' => '#196-Ubuntu SMP {DATE}',
            'gcc' => 'gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38',
            'arch' => 'x86_64 x86_64 x86_64 GNU/Linux', 'fam' => 'debian'],
        ['name' => 'Ubuntu', 'version' => '24.04.1 LTS (Noble Numbat)', 'id' => 'ubuntu', 'vid' => '24.04',
            'pretty' => 'Ubuntu 24.04.1 LTS', 'kernel' => '6.8.0-51-generic', 'uts' => '#52-Ubuntu SMP PREEMPT_DYNAMIC {DATE}',
            'gcc' => 'gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42',
            'arch' => 'x86_64 x86_64 x86_64 GNU/Linux', 'fam' => 'debian'],
        ['name' => 'Debian GNU/Linux', 'version' => '12 (bookworm)', 'id' => 'debian', 'vid' => '12',
            'pretty' => 'Debian GNU/Linux 12 (bookworm)', 'kernel' => '6.1.0-10-amd64', 'uts' => '#1 SMP PREEMPT_DYNAMIC Debian 6.1.38-2 ({DATE})',
            'gcc' => 'gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40',
            'arch' => 'x86_64 GNU/Linux', 'fam' => 'debian'],
        ['name' => 'Debian GNU/Linux', 'version' => '11 (bullseye)', 'id' => 'debian', 'vid' => '11',
            'pretty' => 'Debian GNU/Linux 11 (bullseye)', 'kernel' => '5.10.0-28-amd64', 'uts' => '#1 SMP Debian 5.10.209-2 ({DATE})',
            'gcc' => 'gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2',
            'arch' => 'x86_64 GNU/Linux', 'fam' => 'debian'],
        ['name' => 'Rocky Linux', 'version' => '9.2 (Blue Onyx)', 'id' => 'rocky', 'vid' => '9.2',
            'pretty' => 'Rocky Linux 9.2 (Blue Onyx)', 'kernel' => '5.14.0-284.18.1.el9_2.x86_64', 'uts' => '#1 SMP PREEMPT_DYNAMIC {DATE}',
            'gcc' => 'gcc (GCC) 11.3.1 20221121 (Red Hat 11.3.1-4)', 'arch' => 'x86_64 x86_64 x86_64 GNU/Linux', 'fam' => 'rhel'],
        ['name' => 'Red Hat Enterprise Linux', 'version' => '9.4 (Plow)', 'id' => 'rhel', 'vid' => '9.4',
            'pretty' => 'Red Hat Enterprise Linux 9.4 (Plow)', 'kernel' => '5.14.0-427.31.1.el9_4.x86_64', 'uts' => '#1 SMP PREEMPT_DYNAMIC {DATE}',
            'gcc' => 'gcc (GCC) 11.4.1 20231218 (Red Hat 11.4.1-3)', 'arch' => 'x86_64 x86_64 x86_64 GNU/Linux', 'fam' => 'rhel'],
        ['name' => 'AlmaLinux', 'version' => '9.6 (Sage Margay)', 'id' => 'almalinux', 'vid' => '9.6',
            'pretty' => 'AlmaLinux 9.6 (Sage Margay)', 'kernel' => '5.14.0-570.12.1.el9_6.x86_64', 'uts' => '#1 SMP PREEMPT_DYNAMIC {DATE}',
            'gcc' => 'gcc (GCC) 11.5.0 20240719 (Red Hat 11.5.0-5)', 'arch' => 'x86_64 x86_64 x86_64 GNU/Linux', 'fam' => 'rhel'],
        ['name' => 'CentOS Stream', 'version' => '9', 'id' => 'centos', 'vid' => '9',
            'pretty' => 'CentOS Stream 9', 'kernel' => '5.14.0-124.el9.x86_64', 'uts' => '#1 SMP PREEMPT_DYNAMIC {DATE}',
            'gcc' => 'gcc (GCC) 11.2.1 20220127 (Red Hat 11.2.1-9)', 'arch' => 'x86_64 x86_64 x86_64 GNU/Linux', 'fam' => 'rhel'],
        ['name' => 'Amazon Linux', 'version' => '2023', 'id' => 'amzn', 'vid' => '2023',
            'pretty' => 'Amazon Linux 2023', 'kernel' => '6.1.29-50.88.amzn2023.x86_64', 'uts' => '#1 SMP PREEMPT_DYNAMIC {DATE}',
            'gcc' => 'gcc (GCC) 11.4.1 20230605 (Red Hat 11.4.1-2)', 'arch' => 'x86_64 x86_64 x86_64 GNU/Linux', 'fam' => 'rhel'],
    ];

    // Role-flavored hostname word arrays (operator's roles + infra roles the research documented).
    private const ROLE_KEYS = ['mainframe', 'embedded', 'cctv', 'sales', 'finance', 'devci', 'web', 'db', 'app', 'hypervisor', 'storage', 'k8s'];
    private const ROLE_WORDS = [
        'mainframe' => ['mainframe', 'zos', 'lpar', 'zseries', 'host'],
        'embedded' => ['iot', 'edge', 'sensor', 'plc', 'rtu', 'gw', 'embd'],
        'cctv' => ['cctv', 'nvr', 'dvr', 'vms', 'cam', 'surveil'],
        'sales' => ['sales', 'crm', 'pos', 'quote', 'order'],
        'finance' => ['finance', 'billing', 'erp', 'ledger', 'payroll', 'fin'],
        'devci' => ['ci', 'build', 'runner', 'buildkite', 'jenkins', 'gitlab'],
        'web' => ['web', 'www', 'lb', 'proxy', 'httpd', 'ingress'],
        'db' => ['db', 'sql', 'pg', 'maria', 'mysql', 'oracle'],
        'app' => ['app', 'api', 'svc', 'backend', 'worker'],
        'hypervisor' => ['esx', 'pve', 'kvm', 'vhost', 'xen', 'hv'],
        'storage' => ['storage', 'nas', 'san', 'backup', 'ceph', 'minio'],
        'k8s' => ['k8s', 'node', 'worker', 'kube'],
    ];
    private const ENV = ['prod', 'prod', 'prod', 'stg', 'dev', 'qa', 'uat', 'dr'];
    private const REGION = ['fra', 'use1', 'usw2', 'lon', 'ams', 'sin', 'iad', 'nyc', 'dub', 'syd'];
    private const SITE = ['NYC', 'LON', 'FRA', 'PHX', 'SIN', 'AMS', 'DUB', 'SYD'];
    private const SUBROLE = ['repl', 'core', 'edge', 'dc1', 'dc2', 'b2', 'fl3', 'lobby', 'pool1', 'dr'];
    private const THEME = ['zeus', 'apollo', 'pluto', 'atlas', 'odin', 'thor', 'janus', 'vulcan', 'hermes', 'juno'];
    private const STYLES = ['cloud', 'cloud', 'ad', 'flat', 'infra', 'thematic'];

    /** @param array{name:string,version:string,id:string,vid:string,pretty:string,kernel:string,uts:string,gcc:string,arch:string,fam:string} $d */
    private function __construct(private array $d, private string $hostname)
    {
    }

    public static function fromSeed(int $seed): self
    {
        $base = (string) $seed;
        $distro = self::DISTROS[crc32('kern|' . $base) % count(self::DISTROS)];

        return new self($distro, self::deriveHostname($base));
    }

    public function hostname(): string
    {
        return $this->hostname;
    }

    public function distroPretty(): string
    {
        return $this->d['pretty'];
    }

    public function osReleaseId(): string
    {
        return $this->d['id'];
    }

    public function kernel(): string
    {
        return $this->d['kernel'];
    }

    public function gcc(): string
    {
        return $this->d['gcc'];
    }

    /** Plausible distro kernel build host for /proc/version (not the honeypot itself). */
    public function builder(): string
    {
        switch ($this->d['id']) {
            case 'ubuntu':
                return 'buildd@lcy02-amd64-077';
            case 'debian':
                return 'debian-kernel@lists.debian.org';
            case 'amzn':
                return 'mockbuild@build.amazonlinux.com';
            default: // rhel / rocky / almalinux / centos
                return 'mockbuild@' . $this->d['id'] . 'build.example.org';
        }
    }

    public function archSuffix(): string
    {
        return $this->d['arch'];
    }

    public function family(): string
    {
        return $this->d['fam'];
    }

    /** UTS build-string with the {DATE} filled from a deterministic past instant off the frozen clock. */
    public function uts(): string
    {
        return str_replace('{DATE}', $this->buildDate(), $this->d['uts']);
    }

    public function osRelease(): string
    {
        return "NAME=\"{$this->d['name']}\"\n"
            . "VERSION=\"{$this->d['version']}\"\n"
            . "ID={$this->d['id']}\n"
            . "VERSION_ID=\"{$this->d['vid']}\"\n"
            . "PRETTY_NAME=\"{$this->d['pretty']}\"\n";
    }

    private function buildDate(): string
    {
        // 30–400 days + a seeded intra-day offset before the frozen "now": deterministic per host,
        // plausible, never future, and NOT all sharing epoch's time-of-day (that would be a tell).
        $offset = (30 + crc32('kdate|' . $this->hostname) % 370) * 86400 + crc32('ktime|' . $this->hostname) % 86400;
        $t = FrozenClock::epoch() - $offset;

        return gmdate('D M j H:i:s', $t) . ' UTC ' . gmdate('Y', $t);
    }

    /** crc32(base) sliced into role/style/env/region/seq/letter arrays (operator's scheme). */
    private static function deriveHostname(string $base): string
    {
        $c = crc32($base);
        $roleKey = self::ROLE_KEYS[($c >> 28) % count(self::ROLE_KEYS)];
        $words = self::ROLE_WORDS[$roleKey];
        $role = $words[$c % count($words)];
        $style = self::STYLES[($c >> 4) % count(self::STYLES)];
        $seq = str_pad((string) (1 + ($c >> 16) % 20), 2, '0', STR_PAD_LEFT);

        switch ($style) {
            case 'cloud':
                $env = self::ENV[($c >> 8) % count(self::ENV)];
                $region = self::REGION[($c >> 12) % count(self::REGION)];
                return "{$role}-{$env}-{$region}-{$seq}";
            case 'ad':
                $site = self::SITE[($c >> 24) % count(self::SITE)];
                return strtoupper(substr($site . substr($role, 0, 4) . $seq, 0, 15));
            case 'infra':
                $sub = self::SUBROLE[($c >> 20) % count(self::SUBROLE)];
                return "{$role}-{$sub}-{$seq}";
            case 'thematic':
                return self::THEME[($c >> 6) % count(self::THEME)];
            case 'flat':
            default:
                return "{$role}{$seq}";
        }
    }
}
