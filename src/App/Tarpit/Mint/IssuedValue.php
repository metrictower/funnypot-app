<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\App\Tarpit\InertSecret;
use LogicException;

/**
 * Whether a random value the surface issues, and expects back, is fit to issue. It must be
 * fingerprint-clean, and it must hold no word core's attack rules read as a command, a key file or a
 * dotfile. A value sent back as a form field, a query parameter or a path segment is part of the text
 * those rules scan, so a random token that happens to end in `env` would be logged and reported as an
 * attack on the visitor's own credential.
 *
 * Each list keeps the place its words are read at: the value's start, the start of a part after a `.`
 * (a JWT segment), the value's end, or anywhere; case never matters. The lists hold every such word of up
 * to eight characters on the installed core: TokenMintIssuedWordsTest checks them against it and fails on
 * a missing word or a dead one. A longer word lands at a given place in a random value about once in 10^13.
 *
 * A value that is not fit is re-rolled by stepping a counter in its derivation, so the choice stays
 * deterministic per source. About one form token in twenty thousand is refused, too few for the re-roll
 * to leave a gap a visitor could see. The session cookie rides only in the Cookie header, which those
 * rules never scan, so it needs only the fingerprint check.
 */
final class IssuedValue
{
    /** Read as a command or a file name when a value starts with them. */
    public const START = [
        'aa-', 'addgroup', 'adduser', 'agetty', 'ansible', 'apt-get', 'aria2c', 'arjdisp', 'ascii85', 'aspell',
        'auditctl', 'aurepot', 'ausearch', 'base32', 'basenc', 'bpftrace', 'breaksw', 'bsdcat', 'bsdiff', 'bsdtar',
        'builtin', 'bunzip2', 'busctl', 'busybox', 'byebug', 'bzdiff', 'bzegrep', 'bzfgrep', 'bzgrep', 'bzless',
        'bzmore', 'certbot', 'chef-', 'chflags', 'chpass', 'cobcrun', 'coproc', 'cowsay', 'cowthink', 'cpulimit',
        'crontab', 'csplit', 'csvtool', 'dhclient', 'dmsetup', 'docker-', 'dosbox', 'dpkg-', 'e2fsck', 'exiftool',
        'facter', 'fdmount', 'fdumount', 'filetest', 'foreach', 'fping6', 'ftpstats', 'ftpwho', 'gcc', 'getcap',
        'ghci-', 'groupmod', 'gtester', 'gunzip', 'hexdump', 'hostid', 'hostname', 'hping3', 'htdigest', 'htpasswd', 'ifconfig',
        'ionice', 'ipconfig', 'ippfind', 'ipptool', 'iptables', 'ispell', 'killall', 'ksshell', 'ldconfig',
        'lessecho', 'lessfile', 'lesspipe', 'lftpget', 'loginctl', 'logname', 'logsave', 'losetup', 'ltrace',
        'lualatex', 'luatex', 'lwp-dump', 'lz4cat', 'lzdiff', 'lzgrep', 'lzless', 'lzmadec', 'lzmainfo', 'lzmore',
        'mkfifo', 'mktemp', 'mlocate', 'msgcat', 'msgconv', 'msgmerge', 'msguniq', 'neofetch', 'netcat', 'netplan',
        'netstat', 'nsenter', 'nslookup', 'onintr', 'openssl', 'openvpn', 'openvt', 'passwd', 'pdb2mb', 'pdflatex',
        'pdftex', 'perlsh', 'php-cgi', 'piconv', 'pidstat', 'pkexec', 'pkg_info', 'pkginfo', 'printenv', 'psftp',
        'ptardiff', 'ptargrep', 'python', 'readelf', 'realpath', 'restic', 'rlogin', 'rlwrap', 'rmt-dump', 'rmt-tar',
        'rmuser', 'rpmquery', 'ruby', 'rust-gdb', 'rustdoc', 'rustfmt', 'rustup', 'setarch', 'setcap', 'setenv',
        'setsid', 'soelim', 'sqlite3', 'ssh-add', 'sshpass', 'stdbuf', 'strace', 'sudo-rs', 'sudo_', 'sudoedit',
        'svnadmin', 'svnauthz', 'svnbench', 'svnfsfs', 'svnlook', 'svnmucc', 'svnrdump', 'svnserve', 'svnsync',
        'sysctl', 'taskset', 'tcpdump', 'tcping', 'telnet', 'tshark', 'unexpand', 'unlzma', 'unpigz', 'unzstd',
        'useradd', 'userdel', 'usermod', 'uudecode', 'uuencode', 'valgrind', 'vimdiff', 'visudo', 'whoami',
        'xelatex', 'xmodmap', 'xzdiff', 'xzgrep', 'xzless', 'xzmore', 'zathura', 'zipcloak', 'zipcmp', 'zipgrep',
        'zipinfo', 'zipmerge', 'zipnote', 'zipsplit', 'ziptool', 'zmodload', 'zsoelim', 'zstdcat', 'zstdgrep', 'zstdless',
        'zstdmt', 'zypper',
    ];

    /** Read as a command when a value ends with them; `nohup` is read only with a command after it. */
    public const END = [
        'command', 'env', 'eval',
        'nohup7z', 'nohuparj', 'nohupbzz', 'nohupcmp', 'nohupcsh', 'nohupdf', 'nohupdnf', 'nohupeqn', 'nohupesh',
        'nohupfg', 'nohupfmt', 'nohupgdb', 'nohupgpg', 'nohuphup', 'nohupirb', 'nohupjjs', 'nohupjq', 'nohupls',
        'nohuplz', 'nohuplz4', 'nohupmtr', 'nohuppdb', 'nohuppkg', 'nohupptx', 'nohuppwd', 'nohuppxz', 'nohuprcp', 'nohuprmt',
        'nohupscp', 'nohupsed', 'nohupsh', 'nohupssh', 'nohupsvn', 'nohuptac', 'nohuptbl', 'nohupw3m', 'nohupwc',
        'nohupxxd', 'nohupxz', 'nohupyum',
    ];

    /** Read as a dotfile at the start of a part after a `.`. */
    public const AFTER_DOT = [
        'aiignore', 'bash_', 'bashrc', 'boto', 'coverage', 'crush', 'cshrc', 'cvs', 'ds_store', 'env', 'fbcindex',
        'forward', 'gitkeep', 'hgignore', 'htaccess', 'htdigest', 'htpasswd', 'lesshst', 'lhistory', 'msmtprc', 'netrc', 'npmrc',
        'nsconfig', 'nsr', 'oh-my-', 'pass', 'pearrc', 'pgpass', 'pinerc', 'proclog', 'profile', 'pwd', 'rhistory', 'rhosts',
        'rustup', 's3cfg', 'secrets', 'tcshrc', 'viminfo', 'vimrc', 'vscode', 'www_acl', 'wwwacl', 'yarnrc', 'zhistory',
        'zshenv', 'zshrc',
    ];

    /** Read wherever they sit. */
    public const ANYWHERE = ['id_dsa', 'id_ecdsa', 'id_rsa', 'nohupaa-', 'nohupgcc', 'system32'];

    public static function fit(string $value): bool
    {
        return InertSecret::isClean('"' . $value . '"') && InertSecret::isClean("'" . $value . "'") && self::quiet($value);
    }

    /** Whether no word core's attack rules read sits in the value at the place it is read. */
    public static function quiet(string $value): bool
    {
        $v = strtolower($value);
        foreach (self::ANYWHERE as $w) {
            if (str_contains($v, $w)) {
                return false;
            }
        }
        foreach (self::START as $w) {
            if (str_starts_with($v, $w)) {
                return false;
            }
        }
        foreach (self::END as $w) {
            if (str_ends_with($v, $w)) {
                return false;
            }
        }
        foreach (array_slice(explode('.', $v), 1) as $part) {
            foreach (self::AFTER_DOT as $w) {
                if (str_starts_with($part, $w)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * The first fit value of $gen(0), $gen(1), … (null skips a step). None within $tries is a fault the
     * surface's fault boundary answers, never a flagged or unchecked value.
     *
     * @param callable(int):?string $gen
     */
    public static function first(int $tries, callable $gen): string
    {
        for ($i = 0; $i < $tries; $i++) {
            $value = $gen($i);
            if ($value !== null && self::fit($value)) {
                return $value;
            }
        }

        throw new LogicException('no fit value within the tries');
    }
}
