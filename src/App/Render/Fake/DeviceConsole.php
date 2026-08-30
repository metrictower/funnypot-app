<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic facts for an operational-device console addressed as /{mount}/{device-id} (a POS
 * terminal, a mainframe/host, a PLC/controller, or a generic embedded gateway). Scanners probe these
 * device paths by name and, until now, fell through to the generic admin Dashboard; this gives each a
 * believable per-device identity instead.
 *
 * Design (matches Fake\Appliances / Fake\Cctv):
 *  - DETERMINISTIC: every fact derives from hash(seed | device-id | slot) — no time()/rand(). The same
 *    seed + id always yields byte-identical facts, so a re-probe of the same console never drifts.
 *  - COHERENT: the site is the estate's own site (Building::site()), unless the id embeds a known site
 *    code (e.g. `...-ams-...` -> Amsterdam), in which case the console reports that city so it agrees
 *    with the name the attacker already read off the id. IPs sit in the estate's RFC1918 fabric.
 *  - INERT + FINGERPRINT-SAFE: invented vendor/model/platform names only (never a real product), and
 *    the ip/serial strings open no socket and identify nothing real.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/named-args/promotion/str_contains).
 */
final class DeviceConsole
{
    /** Persona tokens matched against the id's segments (prefix match per segment, so `mf01` -> host
     *  but `comfort` never does). Order is POS, then host, then controller; else a seeded pick. */
    private const POS_TOKENS = ['pos', 'till', 'pdq', 'epos', 'register', 'checkout', 'lane', 'kiosk', 'atm', 'ecr'];
    private const HOST_TOKENS = ['mainframe', 'mf', 'zos', 'os390', 'as400', 'iseries', 'zseries', 'hmc', 'lpar', 'host', 'batch'];
    private const PLC_TOKENS = ['plc', 'scada', 'rtu', 'hmi', 'modbus', 'dcs', 'ics', 'plant', 'sensor', 'actuator', 'ctrl'];
    private const EMBEDDED_TOKENS = ['gw', 'gateway', 'edge', 'iot', 'modem', 'relay', 'probe', 'node'];

    /** Three-letter site codes that commonly appear in device ids -> the city the console reports, so a
     *  `...-ams-...` device says Amsterdam and agrees with its own name. Unmatched -> the estate site. */
    private const SITE_CODES = [
        'ams' => 'Amsterdam', 'lhr' => 'London', 'lon' => 'London', 'iad' => 'Ashburn',
        'dub' => 'Dublin', 'fra' => 'Frankfurt', 'sin' => 'Singapore', 'syd' => 'Sydney',
        'nyc' => 'New York', 'sfo' => 'San Francisco', 'par' => 'Paris', 'mad' => 'Madrid',
        'tor' => 'Toronto', 'chi' => 'Chicago', 'dfw' => 'Dallas', 'sea' => 'Seattle',
    ];

    /** @var int */
    private $seed;

    /** @var string the raw device id (echoed only through esc() by the renderer) */
    private $id;

    /** @var Building */
    private $bld;

    private function __construct(int $seed, string $id)
    {
        $this->seed = $seed;
        $this->id = $id;
        $this->bld = Building::fromSeed($seed);
    }

    /**
     * The full deterministic fact set for one device console.
     *
     * @return array{
     *   id:string, persona:string, personaLabel:string, hostname:string, vendor:string, model:string,
     *   platform:string, firmware:string, serial:string, ip:string, site:string, zone:string,
     *   status:string, statusLabel:string, uptime:string, lastContact:string, detail:list<array{0:string,1:string}>,
     *   activity:list<string>, banner:string
     * }
     */
    public static function forId(int $seed, string $id): array
    {
        return (new self($seed, $id))->facts();
    }

    /**
     * Whether an (unregistered) panel module slug should be treated as a device console rather than the
     * generic Dashboard fallback. True when a segment carries a device token (pos/plc/mainframe/…), OR
     * the slug has the shape of a device name — a hyphenated id ending in digits (`pos-dev-ams-08`) or a
     * short alpha+number tag (`mainframe07`). A plain word module (`reports`, `settings`) matches none,
     * so it keeps its existing Dashboard-fallback behaviour. The caller must already have confirmed the
     * slug is NOT a registered panel section (so real modules are never captured).
     */
    public static function looksLikeDevice(string $slug): bool
    {
        $slug = strtolower($slug);
        $segs = preg_split('/[^a-z0-9]+/', $slug) ?: [];
        $segs = array_values(array_filter($segs, static fn (string $p): bool => $p !== ''));
        if ($segs === []) {
            return false;
        }
        foreach ([self::POS_TOKENS, self::HOST_TOKENS, self::PLC_TOKENS] as $tokens) {
            foreach ($segs as $seg) {
                foreach ($tokens as $token) {
                    if (strpos($seg, $token) === 0) {
                        return true;
                    }
                }
            }
        }

        // Shape: a hyphenated/underscored id ending in digits, or a compact `<letters><digits>` tag.
        if ((strpos($slug, '-') !== false || strpos($slug, '_') !== false) && preg_match('/[0-9]$/', $slug) === 1) {
            return true;
        }

        return preg_match('/^[a-z]{2,}[0-9]{1,4}$/', $slug) === 1;
    }

    /**
     * A deterministic fleet roster for the Devices landing, so the sidebar link resolves to a real list
     * and a crawler reaches coherent device ids it can then open. Each id follows the same shape scanners
     * probe (`pos-dev-ams-08`), and opening one renders its console via forId() with matching facts.
     *
     * @return list<array{id:string,personaLabel:string,site:string,status:string,statusLabel:string}>
     */
    public static function fleet(int $seed): array
    {
        $codes = array_keys(self::SITE_CODES);
        $kinds = [
            ['pos', 'pos-%s-%02d'],
            ['mainframe', 'mainframe%02d'],
            ['plc', 'plc-prod-%s-%02d'],
            ['embedded', 'gw-%s-%02d'],
        ];
        $roster = [];
        for ($i = 0; $i < 12; $i++) {
            $h = (int) hexdec(substr(hash('sha256', $seed . '|dvcfleet|' . $i), 0, 15));
            $kind = $kinds[$h % count($kinds)];
            $code = $codes[($h >> 3) % count($codes)];
            $n = ($h >> 7) % 90 + 1;
            $id = strpos($kind[1], '%s') !== false ? sprintf($kind[1], $code, $n) : sprintf($kind[1], $n);
            $roster[$id] = self::summaryOf($seed, $id);
        }
        ksort($roster);

        return array_values($roster);
    }

    /** @return array{id:string,personaLabel:string,site:string,status:string,statusLabel:string} */
    private static function summaryOf(int $seed, string $id): array
    {
        $d = self::forId($seed, $id);

        return [
            'id' => $d['id'],
            'personaLabel' => $d['personaLabel'],
            'site' => $d['site'],
            'status' => $d['status'],
            'statusLabel' => $d['statusLabel'],
        ];
    }

    // --- deterministic seeded primitives (frozen per seed + id) ---

    private function h(string $salt): int
    {
        return (int) hexdec(substr(hash('sha256', $this->seed . '|dvc|' . $this->id . '|' . $salt), 0, 15));
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

    private function firmware(string $salt): string
    {
        return 'v' . $this->intIn(1, 6, $salt . '|a')
            . '.' . $this->intIn(0, 20, $salt . '|b')
            . '.' . $this->intIn(0, 40, $salt . '|c');
    }

    /** Seeded "N ago" — pure hash(seed+id+slot), never time()/date(). */
    private function ageAgo(string $salt): string
    {
        $sec = $this->intIn(15, 259200, $salt);
        if ($sec < 90) {
            return $sec . ' s ago';
        }
        if ($sec < 5400) {
            return (int) round($sec / 60) . ' min ago';
        }
        if ($sec < 172800) {
            return (int) round($sec / 3600) . ' h ago';
        }

        return (int) round($sec / 86400) . ' d ago';
    }

    private function uptime(string $salt): string
    {
        $days = $this->intIn(1, 940, $salt);
        $hours = $this->intIn(0, 23, $salt . '|h');

        return $days . ' d ' . $hours . ' h';
    }

    /** @return list<string> the id split into lowercase alnum segments */
    private function segments(): array
    {
        $parts = preg_split('/[^a-z0-9]+/', strtolower($this->id)) ?: [];

        return array_values(array_filter($parts, static fn (string $p): bool => $p !== ''));
    }

    private function persona(): string
    {
        $segs = $this->segments();
        $groups = [
            ['pos', self::POS_TOKENS],
            ['mainframe', self::HOST_TOKENS],
            ['plc', self::PLC_TOKENS],
            ['embedded', self::EMBEDDED_TOKENS],
        ];
        foreach ($groups as $group) {
            foreach ($segs as $seg) {
                foreach ($group[1] as $token) {
                    if (strpos($seg, $token) === 0) {
                        return $group[0];
                    }
                }
            }
        }

        return $this->pick(['pos', 'mainframe', 'plc', 'embedded'], 'persona');
    }

    /** The reported city: a site code embedded in the id wins (so the console agrees with its name),
     *  else the estate's own site city. */
    private function site(): string
    {
        foreach ($this->segments() as $seg) {
            if (isset(self::SITE_CODES[$seg])) {
                return self::SITE_CODES[$seg];
            }
        }
        $site = $this->bld->site();

        return (string) ($site['city'] ?? 'HQ');
    }

    /** @return array{0:string,1:string} [vendor, model] — invented names, persona-appropriate. */
    private function vendorModel(string $persona): array
    {
        $vendors = ['Aldergate', 'Northwind', 'Calderis', 'Meridian', 'Halcyon', 'Corvus', 'Brightwell'];
        $vendor = $this->pick($vendors, 'vendor');
        switch ($persona) {
            case 'pos':
                return [$vendor . ' Retail', 'TrustLane ' . $this->pick(['R2', 'R4', 'S3', 'S5'], 'mdl') . '-' . $this->intIn(100, 990, 'mdln')];
            case 'mainframe':
                return [$vendor . ' Systems', 'Enterprise Series ' . $this->pick(['E7', 'E9', 'M8', 'M9'], 'mdl') . $this->intIn(10, 90, 'mdln')];
            case 'plc':
                return [$vendor . ' Automation', 'LogiCell ' . $this->pick(['LX', 'CX', 'PX'], 'mdl') . '-' . $this->intIn(200, 880, 'mdln')];
            default:
                return [$vendor . ' Edge', 'GateCore ' . $this->pick(['G2', 'G4', 'N3'], 'mdl') . '-' . $this->intIn(10, 99, 'mdln')];
        }
    }

    private function platform(string $persona): string
    {
        switch ($persona) {
            case 'pos':
                return $this->pick(['RetailCore', 'PosixPay Terminal', 'LaneOS'], 'plat') . ' ' . $this->intIn(3, 9, 'platv') . '.' . $this->intIn(0, 9, 'platm');
            case 'mainframe':
                return $this->pick(['CoreExec', 'BatchServe', 'HostControl'], 'plat') . ' ' . $this->intIn(4, 12, 'platv') . '.' . $this->intIn(0, 4, 'platm');
            case 'plc':
                return $this->pick(['LadderRT', 'CtrlCore', 'FieldLink'], 'plat') . ' ' . $this->intIn(2, 8, 'platv') . '.' . $this->intIn(0, 9, 'platm');
            default:
                return $this->pick(['NodeCtl', 'MicroGW', 'GwCore'], 'plat') . ' ' . $this->intIn(1, 6, 'platv') . '.' . $this->intIn(0, 9, 'platm');
        }
    }

    /** Persona-appropriate zone + inert RFC1918 ip subnet + status hint. */
    private function facts(): array
    {
        $persona = $this->persona();
        [$vendor, $model] = $this->vendorModel($persona);

        $map = [
            'pos' => ['label' => 'Point-of-Sale Terminal', 'zone' => 'Retail Floor', 'net' => 60],
            'mainframe' => ['label' => 'Host / Mainframe', 'zone' => 'Data Centre', 'net' => 20],
            'plc' => ['label' => 'PLC / Controller', 'zone' => 'Plant Floor', 'net' => 90],
            'embedded' => ['label' => 'Embedded Gateway', 'zone' => 'Comms Room', 'net' => 55],
        ];
        $m = $map[$persona];

        $ip = '10.0.' . $m['net'] . '.' . $this->intIn(11, 240, 'ip');
        $firmware = $this->firmware('fw');
        $platform = $this->platform($persona);
        $site = $this->site();
        $serial = strtoupper($this->pick(['SN', 'AS', 'DV'], 'snp')) . '-' . $this->intIn(100000, 999999, 'sn');

        // A small fraction of consoles report a soft warning, so the fleet does not look implausibly clean.
        $stWarn = $this->h('st') % 5 === 0;
        $status = $stWarn ? 'warn' : 'ok';
        $statusLabel = $stWarn ? $this->pick(['Degraded', 'Attention', 'Sync pending'], 'stl') : 'Online';

        $detail = [
            ['Device ID', $this->id],
            ['Type', $m['label']],
            ['Vendor', $vendor],
            ['Model', $model],
            ['Platform', $platform],
            ['Firmware', $firmware],
            ['Serial', $serial],
            ['Management IP', $ip],
            ['Site', $site],
            ['Zone', $m['zone']],
            ['Uptime', $this->uptime('up')],
            ['Last contact', $this->ageAgo('seen')],
        ];

        $banner = $vendor . ' ' . $model . '  —  ' . $platform . "\n"
            . 'host ' . $this->id . '  (' . $ip . ')  ' . $site . ' / ' . $m['zone'] . "\n"
            . 'firmware ' . $firmware . '   serial ' . $serial;

        return [
            'id' => $this->id,
            'persona' => $persona,
            'personaLabel' => $m['label'],
            'hostname' => $this->id,
            'vendor' => $vendor,
            'model' => $model,
            'platform' => $platform,
            'firmware' => $firmware,
            'serial' => $serial,
            'ip' => $ip,
            'site' => $site,
            'zone' => $m['zone'],
            'status' => $status,
            'statusLabel' => $statusLabel,
            'uptime' => $this->uptime('up'),
            'lastContact' => $this->ageAgo('seen'),
            'detail' => $detail,
            'activity' => $this->activity($persona),
            'banner' => $banner,
        ];
    }

    /** A short, deterministic recent-activity log, persona-flavoured. Canned lines only; nothing real. */
    private function activity(string $persona): array
    {
        $events = [
            'pos' => ['batch settlement completed', 'operator sign-in', 'receipt printer OK', 'card reader heartbeat', 'price file sync', 'drawer opened', 'EOD report queued'],
            'mainframe' => ['batch window started', 'region recycled', 'dataset backup OK', 'operator console msg', 'subsystem healthy', 'spool checkpoint', 'job class drained'],
            'plc' => ['scan cycle nominal', 'I/O module online', 'setpoint applied', 'watchdog reset', 'diagnostic poll OK', 'tag table synced', 'run mode confirmed'],
            'embedded' => ['tunnel keepalive', 'config pulled', 'ntp sync OK', 'link up', 'telemetry flushed', 'watchdog OK', 'cert rotated'],
        ];
        $pool = $events[$persona];
        $lines = [];
        $count = $this->intIn(5, 8, 'aln');
        for ($i = 0; $i < $count; $i++) {
            $mins = $this->intIn(1, 720, 'am' . $i) + $i * 3;
            $lines[] = sprintf('[t-%3dm] %s', $mins, $this->pick($pool, 'ae' . $i));
        }

        return $lines;
    }
}
