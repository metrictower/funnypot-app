<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT fake cron table + process list for the admin-panel skins — every line is its
 * own rabbit hole (fetch the referenced script, probe the bucket, hunt the token) so an attacker
 * burns time chasing dead ends.
 *
 * Design rules (from the fake-data research + adversarial critique, docs/research/2026-08-23-*):
 *  - Frozen per seed: same host tells the same story across refreshes and across panels.
 *  - INERT: no real credentials/keys/buckets; the "secret" args are literal REDACTED / random hex
 *    tokens that authenticate nowhere. Referenced paths and hosts are display-only decoys.
 *  - SAFE: any IP the host reaches (rsync/replica peers) is RFC1918/TEST-NET only, never real space.
 *  - Coherent loot: a single per-seed bucket/db threads through the commands so the story reconciles
 *    if an attacker cross-reads two lines.
 *  - ONE DOMAIN: the heartbeat endpoint renders at the host persona domain when the caller supplies it
 *    (one host = one domain), never a second invented public domain; standalone it falls back to a
 *    clearly-internal RFC1918 service host.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format), matching ServerProfile.
 */
final class FakeCron
{
    use SeededInstanceCache;

    /** @var int */
    private $seed;

    /** @var string host persona domain the heartbeat renders at ('' -> internal RFC1918 fallback). */
    private $personaDomain;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->personaDomain = $personaDomain;
    }

    /**
     * Build a fake cron table for a seed. Callers that render the heartbeat SHOULD pass the host persona
     * domain so it never contradicts the one domain shown elsewhere; the default '' is for standalone use.
     */
    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return self::seededInstance(
            $seed . '|' . $personaDomain,
            static function () use ($seed, $personaDomain): self {
                return new self($seed, $personaDomain);
            }
        );
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        return (int) hexdec(substr(hash('sha256', $this->seed . '|cron|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    private function hex(int $len, string $salt): string
    {
        return substr(hash('sha256', $this->seed . '|hex|' . $salt), 0, $len);
    }

    /** One decimal percent from a tenths range, e.g. pct(400,1180,'x') -> "40.0".."118.0". */
    private function pct(int $minTenths, int $maxTenths, string $salt): string
    {
        return number_format($this->intIn($minTenths, $maxTenths, $salt) / 10, 1);
    }

    // --- per-seed loot identity threaded through the commands ---

    private function bucket(): string
    {
        return $this->pick(['brightpeak', 'nordicav', 'apexfit', 'maplegrove', 'lumenstack'], 'bucket');
    }

    /**
     * The heartbeat endpoint. Persona domain when the caller supplied it (one host = one domain);
     * otherwise a clearly-internal RFC1918 service host — never a second invented public domain.
     */
    private function heartbeatUrl(): string
    {
        if ($this->personaDomain !== '') {
            return 'https://api.' . $this->personaDomain . '/v1/heartbeat/sync';
        }
        return 'https://10.0.5.' . $this->intIn(10, 240, 'hbhost') . '/v1/heartbeat/sync';
    }

    private function db(): string
    {
        return $this->pick(['wp_prod', 'app_production', 'shop_live', 'crm_prod', 'billing'], 'db');
    }

    // --- cron table ---

    /**
     * 8-16 crontab rows, newest secrets first. Schedules cluster 00-04:MM (MM in {00,05,15,30,45})
     * like real overnight batch windows. Commands carry the bait: mysqldump, s3 sync, a Bearer
     * token, --key=REDACTED, certbot, rclone, an RFC1918 rsync peer.
     *
     * @return list<array{schedule:string,user:string,command:string}>
     */
    public function cronJobs(): array
    {
        $b = $this->bucket();
        $db = $this->db();
        $tok = $this->hex(40, 'bearer');           // inert 40-hex token; authenticates nowhere

        // Juicy anchors sit in the first 8 so even the minimum slice keeps the secrets on screen.
        $pool = [
            [$this->sched('daily', 's0'),   'root',
                '/usr/bin/mysqldump --single-transaction --databases ' . $db . ' | gzip > /var/backups/' . $db . '.sql.gz'],
            [$this->sched('daily', 's1'),   'root',
                '/usr/local/bin/backup.sh --dest s3://' . $b . '-backups --key=REDACTED'],
            [$this->sched('daily', 's2'),   'root',
                '/usr/bin/curl -fsS -H "Authorization: Bearer ' . $tok . '" ' . $this->heartbeatUrl()],
            [$this->sched('weekly', 's3'),  'root',
                '/usr/bin/aws s3 sync /var/backups s3://' . $b . '-backups --delete'],
            [$this->sched('daily', 's4'),   'root',
                '/usr/bin/rclone sync /var/www ' . $b . '-remote:offsite --transfers 8'],
            [$this->sched('daily', 's5'),   'root',
                '/usr/bin/certbot renew --quiet --post-hook "systemctl reload nginx"'],
            [$this->sched('daily', 's6'),   'www-data',
                '/usr/bin/php /var/www/html/wp-cron.php >/dev/null 2>&1'],
            [$this->sched('weekly', 's7'),  'postgres',
                '/usr/bin/pg_dump -Fc app_production > /var/backups/pg/app_$(date +%F).dump'],
            [$this->sched('daily', 's8'),   'root',
                '/usr/bin/rsync -az /var/backups/ backup@10.0.0.5:/vol/backups/'],
            [$this->sched('daily', 's9'),   'root',
                '/usr/sbin/logrotate /etc/logrotate.conf'],
            [$this->sched('daily', 's10'),  'root',
                "/usr/bin/find /var/log -name '*.gz' -mtime +30 -delete"],
            [$this->sched('daily', 's11'),  'mysql',
                '/usr/bin/mysqlcheck --optimize --all-databases'],
            [$this->sched('daily', 's12'),  'root',
                '/usr/bin/docker system prune -af'],
            [$this->sched('monthly', 's13'), 'root',
                '/usr/bin/rkhunter --cronjob --update --quiet'],
            [$this->sched('daily', 's14'),  'deploy',
                '/usr/local/bin/deploy-pull.sh --branch main --token REDACTED'],
            [$this->sched('daily', 's15'),  'root',
                '/usr/bin/borg create /mnt/borg::' . $b . '-{now} /etc /var/www'],
        ];

        $count = $this->intIn(8, 16, 'croncount');
        $rows = [];
        for ($i = 0; $i < $count; $i++) {
            $p = $pool[$i];
            $rows[] = ['schedule' => $p[0], 'user' => $p[1], 'command' => $p[2]];
        }
        return $rows;
    }

    /**
     * A crontab schedule field clustered in the 00-04 overnight window.
     * type: 'daily' -> "M H * * *"; 'weekly' -> "M H * * D"; 'monthly' -> "M H DOM * *".
     */
    private function sched(string $type, string $salt): string
    {
        $minute = (int) $this->pick(['0', '5', '15', '30', '45'], 'min' . $salt);
        $hour = $this->intIn(0, 4, 'hr' . $salt);
        if ($type === 'weekly') {
            return sprintf('%d %d * * %d', $minute, $hour, $this->intIn(0, 6, 'dow' . $salt));
        }
        if ($type === 'monthly') {
            return sprintf('%d %d %d * *', $minute, $hour, $this->intIn(1, 28, 'dom' . $salt));
        }
        return sprintf('%d %d * * *', $minute, $hour);
    }

    // --- process list ---

    /**
     * 12-24 rows of a plausible `ps aux`: PID (monotonic ascending), owner, %CPU, %MEM, full
     * command-line. Real daemons (mariadbd, nginx, php-fpm, redis, dockerd, postgres, node) plus a
     * couple of juicy ones — a backup script with --key=REDACTED, a python reading
     * --config /etc/app/secrets.yaml, an RFC1918 rsync peer — kept inside the first 12 (13 when a
     * miner row is also injected) so the minimum slice still shows them.
     *
     * $miner, when non-empty, corroborates a "Miner detected: ACTIVE" card elsewhere on the page: it
     * carries that card's own algo/pool/wallet (keys 'algo','pool','wallet') so this ps table shows a
     * matching miner process instead of leaving the alert uncorroborated by any running process.
     *
     * @param array{algo?:string,pool?:string,wallet?:string} $miner
     * @return list<array{pid:string,user:string,cpu:string,mem:string,command:string}>
     */
    public function processes(array $miner = []): array
    {
        $b = $this->bucket();

        // [user, cpuMinTenths, cpuMaxTenths, memMinTenths, memMaxTenths, command]
        $pool = [
            ['root', 0, 2, 1, 4, '/sbin/init'],
            ['root', 0, 5, 2, 8, '/lib/systemd/systemd-journald'],
            ['root', 0, 4, 3, 9, '/usr/sbin/sshd -D'],
            ['mysql', 400, 1180, 180, 245, '/usr/sbin/mariadbd'],
            ['root', 2, 12, 6, 18, 'nginx: master process /usr/sbin/nginx'],
            ['www-data', 10, 240, 8, 34, 'nginx: worker process'],
            ['www-data', 8, 190, 12, 42, 'php-fpm: pool www'],
            ['root', 2, 40, 8, 26,
                '/usr/bin/python3 /opt/etl/pipeline.py --config /etc/app/secrets.yaml'],
            ['root', 0, 60, 4, 14,
                '/bin/bash /usr/local/bin/backup.sh --dest s3://' . $b . '-backups --key=REDACTED'],
            ['redis', 6, 90, 40, 130, 'redis-server 127.0.0.1:6379'],
            ['postgres', 4, 120, 90, 210, 'postgres: 14/main: walwriter'],
            ['root', 0, 180, 6, 20, '/usr/bin/rsync -az /var/backups/ backup@10.0.0.5:/vol/backups/'],
            ['root', 4, 70, 30, 95, '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock'],
            ['root', 2, 40, 20, 70, '/usr/bin/containerd'],
            ['prometheus', 8, 120, 40, 140, '/usr/bin/prometheus --config.file=/etc/prometheus/prometheus.yml'],
            ['www-data', 6, 160, 30, 110, '/usr/bin/node /var/www/app/server.js'],
            ['mongodb', 4, 90, 60, 180, '/usr/bin/mongod --config /etc/mongod.conf'],
            ['postgres', 0, 20, 30, 90, 'postgres: app_production app 10.0.0.9(51324) idle'],
            ['chrony', 0, 2, 1, 3, '/usr/sbin/chronyd -F 1'],
            ['messagebus', 0, 3, 1, 4, '/usr/bin/dbus-daemon --system --address=systemd:'],
            ['systemd+', 0, 4, 2, 6, '/lib/systemd/systemd-resolved'],
            ['root', 0, 6, 2, 7, '/usr/sbin/rsyslogd -n -iNONE'],
            ['root', 0, 3, 1, 4, '/usr/sbin/cron -f'],
            ['root', 0, 5, 2, 8, '/usr/lib/postfix/sbin/master -w'],
        ];

        if ($miner !== []) {
            // Inside the guaranteed first-13 slice (right after the secrets.yaml python line) so it
            // survives even the minimum row count — the alert always has a process backing it up.
            array_splice($pool, 8, 0, [$this->minerProcessRow($miner)]);
        }

        $count = $this->intIn($miner !== [] ? 13 : 12, 24, 'proccount');
        $pid = 1;
        $rows = [];
        for ($i = 0; $i < $count; $i++) {
            $p = $pool[$i];
            $rows[] = [
                'pid' => (string) $pid,
                'user' => $p[0],
                'cpu' => $this->pct($p[1], $p[2], 'pcpu' . $i),
                'mem' => $this->pct($p[3], $p[4], 'pmem' . $i),
                'command' => $p[5],
            ];
            // Monotonic ascending PIDs, seeded jitter — reads like a real ps snapshot.
            $pid += $this->intIn(3, 900, 'pidgap' . $i);
        }
        return $rows;
    }

    /**
     * A GPU-miner process row matching the "Miner detected" card's own algo/pool/wallet. lolMiner
     * supports both Etchash and KawPow, so one binary stays coherent whichever coin the card picked.
     * A GPU miner's controller process is CPU-light (the hashing runs on the cards) — modest %CPU/%MEM.
     *
     * @param array{algo?:string,pool?:string,wallet?:string} $miner
     * @return array{0:string,1:int,2:int,3:int,4:int,5:string}
     */
    private function minerProcessRow(array $miner): array
    {
        $algo = strtoupper($miner['algo'] ?? 'ETCHASH');
        $command = sprintf(
            '/opt/miner/lolMiner --algo %s --pool %s --wallet %s.rig01 --log',
            $algo,
            $miner['pool'] ?? '',
            $miner['wallet'] ?? ''
        );
        return ['root', 20, 180, 10, 60, $command];
    }
}
