<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT IT-estate corpora for the deep office panel (spec §C.7) — printers/MFPs, software
 * licences, the MDM endpoint fleet, mail admin and certificates. Every corpus is a VIEW over the shared
 * spines: a printer sits in a real `Building` room, a mailbox belongs to a real `Org` employee at the
 * host's one domain, an endpoint's owner + last-IP come straight from that employee's roster record, so
 * the estate reconciles with every other module an attacker cross-references.
 *
 * Design rules (deep-admin dashboard spec §C.7 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); every date is off the one frozen clock (FrozenClock), so a static
 *    reload is byte-identical and never a tell.
 *  - COHERENT: mailbox/MDM magnitudes derive from Org::magnitudes() (mailboxes ~= N, endpoints ~= 1.3N)
 *    so a 214-person company never shows an impossible fleet. Owners/addresses are real roster members.
 *  - SAFE: all addressing is RFC1918 (printers 10.0.24.x, service hosts 10.0.5.x, endpoints on the
 *    employee VLAN via Org). Licence keys are masked at rest and NON-VALIDATING on reveal; certificate
 *    private material is never emitted (downloads are inert decoy archives). Invented model/brand names
 *    only (spec E7) — no real product markup, no scanner-signature string.
 *  - ONE DOMAIN: mailbox/scan/cert-subject addresses render at the host persona domain (passed in). The
 *    single budgeted suspicious external forwarding rule is the deliberate anomaly — its target is a
 *    clearly-fake reserved (.example) domain, never a real mailbox.
 *  - ANOMALY BUDGET: at most one suspicious mail-forwarding rule and a couple of soon-to-expire certs;
 *    most rows read clean.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/promotion/str_contains/arrow fns) so a fact can
 *    promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class ItServices
{
    use SeededInstanceCache;

    /** @var int */
    private $seed;

    /** @var string host persona domain — mailbox/scan/cert addresses render here (one host = one domain). */
    private $domain;

    /** @var Org */
    private $org;

    /** @var Building */
    private $building;

    /** @var Cmdb|null asset inventory, built lazily — the estate the MDM fleet is a managed view over. */
    private $cmdb = null;

    /** @var array<string,list<array{hostname:string,serial:string}>>|null CMDB endpoints grouped by type. */
    private $cmdbEndpoints = null;

    /** @var array<int,array>|null cached flat room list across all floors (printer locations). */
    private $rooms = null;

    private function __construct(int $seed, string $domain)
    {
        $this->seed = $seed;
        $this->domain = $domain;
        $this->org = Org::fromSeed($seed, $domain);
        $this->building = Building::fromSeed($seed);
    }

    public static function fromSeed(int $seed, string $domain = ''): self
    {
        return self::seededInstance(
            $seed . '|' . $domain,
            static function () use ($seed, $domain): self {
                return new self($seed, $domain);
            }
        );
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|it|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    /** @param list<int> $options */
    private function pickInt(array $options, string $salt): int
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    private function dayBack(int $daysBack): string
    {
        return FrozenClock::ymdFromDays(FrozenClock::nowDays() - $daysBack);
    }

    private function dayAhead(int $daysAhead): string
    {
        return FrozenClock::ymdFromDays(FrozenClock::nowDays() + $daysAhead);
    }

    /** Colon-separated hex ($bytes long) derived from the seed+slot — for serials/fingerprints. */
    private function hexColon(int $bytes, string $salt): string
    {
        $hex = strtoupper(substr(hash('sha256', $this->seed . '|itx|' . $salt), 0, $bytes * 2));
        $parts = str_split($hex, 2);
        return implode(':', $parts);
    }

    /**
     * Short host prefix derived from the persona domain stem — identical to the CMDB rule, so MDM and the
     * asset inventory name endpoints in the same namespace.
     */
    private function hostPrefix(): string
    {
        $stem = strtoupper((string) preg_replace('/[^a-z]/', '', strtolower($this->org->domain())));
        $stem = substr($stem, 0, 3);
        return $stem !== '' ? $stem : 'COR';
    }

    /** The one flat room list across every floor — a printer's physical location. */
    private function rooms(): array
    {
        if ($this->rooms !== null) {
            return $this->rooms;
        }
        $flat = [];
        foreach ($this->building->floors() as $f) {
            foreach ($this->building->roomsFor($f['code']) as $r) {
                $flat[] = $r;
            }
        }
        $this->rooms = $flat !== [] ? $flat : [['name' => 'Server-Comms 01', 'floor' => 'G']];
        return $this->rooms;
    }

    // =====================================================================
    // Printers / MFPs
    // =====================================================================

    public function printerCount(): int
    {
        return $this->intIn(8, 40, 'prncount');
    }

    /**
     * One page of printers by absolute offset.
     *
     * @return list<array> each element is a full printerAt() record
     */
    public function printerPage(int $offset, int $limit): array
    {
        return $this->page($this->printerCount(), $offset, $limit, 'printerAt');
    }

    /**
     * One MFP by 0-based index — physically located in a real Building room. Toner cartridges, queue depth
     * and scan-to-email config are all seeded; the SMTP account the device scans through is masked.
     *
     * @return array{index:int,id:string,model:string,location:string,floor:string,ip:string,status:string,queueJobs:int,tonerBlack:int,tonerCyan:int,tonerMagenta:int,tonerYellow:int,scanToEmail:string,smtpUserMasked:string,serial:string,firmware:string,lastSeen:string}
     */
    public function printerAt(int $i): array
    {
        $room = $this->rooms()[$this->h('prn-room|' . $i) % count($this->rooms())];
        $brand = $this->pick(['Xantek', 'Corvex', 'Toneworks', 'Printek', 'Omniprint', 'Meridian'], 'prn-b|' . $i);
        $model = $brand . ' ' . $this->pick(['MX', 'CX', 'PR', 'WX'], 'prn-ml|' . $i) . '-' . $this->intIn(2000, 8900, 'prn-mn|' . $i);
        $status = $this->pick(['Ready', 'Ready', 'Ready', 'Printing', 'Toner low', 'Paper jam', 'Offline'], 'prn-st|' . $i);

        $id = 'mfp-' . strtolower((string) $room['floor']) . '-' . sprintf('%02d', $i + 1);
        return [
            'index' => $i,
            'id' => $id,
            'model' => $model,
            'location' => $room['name'] . ' (Floor ' . $room['floor'] . ')',
            'floor' => (string) $room['floor'],
            'ip' => '10.0.24.' . (10 + ($i % 240)),
            'status' => $status,
            'queueJobs' => $this->intIn(0, 14, 'prn-q|' . $i),
            'tonerBlack' => $this->intIn(3, 100, 'prn-tk|' . $i),
            'tonerCyan' => $this->intIn(3, 100, 'prn-tc|' . $i),
            'tonerMagenta' => $this->intIn(3, 100, 'prn-tm|' . $i),
            'tonerYellow' => $this->intIn(3, 100, 'prn-ty|' . $i),
            'scanToEmail' => 'scan.' . $id . '@' . $this->domain,
            'smtpUserMasked' => 'svc-scan••••',
            'serial' => 'SN' . $this->hexColon(4, 'prn-sn|' . $i),
            'firmware' => 'fw ' . $this->intIn(1, 6, 'prn-fa|' . $i) . '.' . $this->intIn(0, 40, 'prn-fb|' . $i),
            'lastSeen' => $this->intIn(1, 90, 'prn-ls|' . $i) . ' min ago',
        ];
    }

    public function printerById(string $slug): array
    {
        $i = $this->indexFromNumericTail($slug, 1, $this->printerCount());
        if ($i !== null) {
            return $this->printerAt($i);
        }
        return $this->printerAt($this->h('synprn|' . $slug) % $this->printerCount());
    }

    /**
     * The queued print jobs on one printer — each owned by a real Org employee.
     *
     * @return list<array{jobId:string,owner:string,document:string,pages:int,submitted:string,status:string}>
     */
    public function printerQueue(array $printer): array
    {
        $n = $this->org->headcount();
        $roster = $this->org->people($n);
        $docs = ['Q3_forecast.xlsx', 'onboarding_pack.pdf', 'contract_draft.docx', 'floorplan.pdf',
                 'expense_report.pdf', 'name_badges.pdf', 'shipping_labels.pdf', 'agenda.docx'];
        $states = ['Printing', 'Queued', 'Held', 'Spooling'];
        $out = [];
        $count = (int) $printer['queueJobs'];
        for ($k = 0; $k < $count; $k++) {
            $salt = 'pq|' . $printer['id'] . '|' . $k;
            $owner = $roster[$this->h($salt . '|o') % $n];
            $out[] = [
                'jobId' => 'job-' . sprintf('%05d', 10000 + ($this->h($salt . '|j') % 90000)),
                'owner' => $owner['name'],
                'document' => $docs[$this->h($salt . '|d') % count($docs)],
                'pages' => $this->intIn(1, 180, $salt . '|p'),
                'submitted' => $this->intIn(1, 240, $salt . '|s') . ' min ago',
                'status' => $states[$this->h($salt . '|st') % count($states)],
            ];
        }
        return $out;
    }

    // =====================================================================
    // Software licences
    // =====================================================================

    public function licenseCount(): int
    {
        return $this->intIn(30, 120, 'liccount');
    }

    /** @return list<array> */
    public function licensePage(int $offset, int $limit): array
    {
        return $this->page($this->licenseCount(), $offset, $limit, 'licenseAt');
    }

    /**
     * One licence by 0-based index. Seats used never exceed seats total; the product key is masked at
     * rest — its real value is never generated, only a NON-VALIDATING per-key dummy (see keyReveal()).
     *
     * @return array{index:int,id:string,product:string,vendor:string,edition:string,seatsUsed:int,seatsTotal:int,keyMasked:string,expiry:string,supportTier:string}
     */
    public function licenseAt(int $i): array
    {
        $product = $this->pick(
            ['AtlasCAD', 'NimbusOffice Suite', 'SentryGuard EDR', 'CodeForge IDE', 'LedgerPro',
             'VaultDB', 'PixelWorks Studio', 'MeetSpace', 'HelpdeskPro', 'BackupVault',
             'FirewallManager', 'SignFlow', 'DataMesh Analytics', 'MailGuard'],
            'lic-p|' . $i
        );
        $total = $this->pickInt([10, 25, 50, 100, 250, 500], 'lic-tot|' . $i);
        $used = $this->intIn((int) round($total * 0.3), $total, 'lic-used|' . $i);
        return [
            'index' => $i,
            'id' => 'lic-' . sprintf('%04d', 1001 + $i),
            'product' => $product,
            'vendor' => $this->pick(['Northwind Software', 'Vertex Systems', 'Clearpath Ltd', 'Beacon Labs', 'Ironvale Inc'], 'lic-v|' . $i),
            'edition' => $this->pick(['Enterprise', 'Business', 'Standard', 'Team'], 'lic-ed|' . $i),
            'seatsUsed' => $used,
            'seatsTotal' => $total,
            'keyMasked' => 'XXXXX-XXXXX-XXXXX-••••' . sprintf('%04d', $this->h('lic-kt|' . $i) % 10000),
            'expiry' => $this->dayAhead($this->intIn(20, 900, 'lic-exp|' . $i)),
            'supportTier' => $this->pick(['Premier', 'Standard', 'Basic'], 'lic-sup|' . $i),
        ];
    }

    public function licenseById(string $slug): array
    {
        $i = $this->indexFromNumericTail($slug, 1001, $this->licenseCount());
        if ($i !== null) {
            return $this->licenseAt($i);
        }
        return $this->licenseAt($this->h('synlic|' . $slug) % $this->licenseCount());
    }

    /**
     * A per-key reveal dummy in the right shape — deterministic per key, but structurally a placeholder
     * (the trailing group reads EXAMP) so a copied value validates against nothing (spec E5/E10).
     */
    public function keyReveal(array $license): string
    {
        $groups = [];
        for ($g = 0; $g < 4; $g++) {
            $groups[] = strtoupper(substr(hash('sha256', $this->seed . '|lickey|' . $license['id'] . '|' . $g), 0, 5));
        }
        return implode('-', $groups) . '-EXAMP';
    }

    // =====================================================================
    // MDM endpoint fleet
    // =====================================================================

    /** Fleet size derives from Org (endpoints ~= assets ~= 1.3N) so magnitudes reconcile (spec E3). */
    public function mdmCount(): int
    {
        return $this->org->magnitudes()['mdmEnrolled'];
    }

    /** The shared asset inventory, built lazily — the MDM fleet draws its hostnames/serials from it. */
    private function cmdb(): Cmdb
    {
        if ($this->cmdb === null) {
            $this->cmdb = Cmdb::fromSeed($this->seed, $this->domain);
        }
        return $this->cmdb;
    }

    /**
     * CMDB endpoint hostname+serial pairs grouped by asset type (built once). The MDM fleet is a managed
     * VIEW over these real assets, so its hostnames/serials are drawn from the inventory rather than a
     * disjoint 01001+ namespace — a list-diff against the CMDB overlaps instead of reading as two fleets.
     *
     * @return array<string,list<array{hostname:string,serial:string}>>
     */
    private function cmdbEndpoints(): array
    {
        if ($this->cmdbEndpoints !== null) {
            return $this->cmdbEndpoints;
        }
        $byType = ['laptop' => [], 'desktop' => [], 'phone' => [], 'tablet' => []];
        foreach ($this->cmdb()->assets() as $a) {
            if (isset($byType[$a['type']]) && $a['hostname'] !== '—') {
                $byType[$a['type']][] = ['hostname' => $a['hostname'], 'serial' => $a['serial']];
            }
        }
        $this->cmdbEndpoints = $byType;
        return $byType;
    }

    /** @return list<array> */
    public function mdmPage(int $offset, int $limit): array
    {
        return $this->page($this->mdmCount(), $offset, $limit, 'mdmDeviceAt');
    }

    /**
     * One enrolled endpoint by 0-based index. Its owner and last-known IP come straight from the Org
     * roster (owner i mod N), so the device reconciles with the HR directory and the employee VLAN.
     *
     * @return array{index:int,id:string,hostname:string,owner:string,ownerEmail:string,os:string,osVersion:string,model:string,serial:string,compliance:string,ip:string,lastSync:string,enrolled:string,encrypted:string}
     */
    public function mdmDeviceAt(int $i): array
    {
        $n = $this->org->headcount();
        $owner = $this->org->people($n)[$i % $n];
        $osIdx = $this->h('mdm-os|' . $i) % 5;
        $osList = ['Windows 11 Pro', 'macOS', 'iOS', 'Android', 'iPadOS'];
        $verList = ['23H2', '14.5', '17.5', '14', '17.5'];
        $modelList = ['PortaBook 14', 'PortaBook Air', 'SlateTab 11', 'FieldPhone X', 'FieldPhone Mini'];

        $r = $this->h('mdm-comp|' . $i) % 100;
        $compliance = $r < 82 ? 'Compliant' : ($r < 95 ? 'At risk' : 'Non-compliant');

        // Hostname + serial are a REAL CMDB endpoint's, of the class this device's OS implies (macOS/
        // Windows -> laptop/desktop, iPadOS -> tablet, iOS/Android -> phone), so the managed fleet is a
        // subset of the asset inventory an attacker can diff, never a second disjoint 01001+ population.
        if ($osIdx === 0) {
            $classes = ['laptop', 'desktop'];
        } elseif ($osIdx === 1) {
            $classes = ['laptop'];
        } elseif ($osIdx === 4) {
            $classes = ['tablet'];
        } else {
            $classes = ['phone'];
        }
        $byType = $this->cmdbEndpoints();
        $pool = [];
        foreach ($classes as $c) {
            foreach ($byType[$c] as $ep) {
                $pool[] = $ep;
            }
        }
        if ($pool === []) {
            // No CMDB endpoint of this class for the seed: draw from any endpoint so the fleet still
            // reconciles with the inventory (subset holds); only a monitor-only estate would empty this.
            foreach ($byType as $eps) {
                foreach ($eps as $ep) {
                    $pool[] = $ep;
                }
            }
        }
        if ($pool !== []) {
            $ep = $pool[$this->h('mdm-host|' . $i) % count($pool)];
            $hostname = $ep['hostname'];
            $serial = $ep['serial'];
        } else {
            // Degenerate fallback (no hostnamed asset at all): keep a self-consistent name/serial.
            $typeCode = $osIdx <= 1 ? 'LT' : ($osIdx === 4 ? 'TB' : 'PH');
            $hostname = $this->hostPrefix() . '-' . $typeCode . '-' . sprintf('%05d', 1001 + $i);
            $serial = strtoupper(substr(hash('sha256', $this->seed . '|mdmsn|' . $i), 0, 3))
                . sprintf('%07d', $this->intIn(0, 9999999, 'mdmsn2|' . $i));
        }

        return [
            'index' => $i,
            'id' => 'dev-' . sprintf('%05d', 20001 + $i),
            'hostname' => $hostname,
            'owner' => $owner['name'],
            'ownerEmail' => $owner['email'],
            'os' => $osList[$osIdx],
            'osVersion' => $verList[$osIdx],
            'model' => $modelList[$this->h('mdm-md|' . $i) % count($modelList)],
            'serial' => $serial,
            'compliance' => $compliance,
            'ip' => $owner['ip'],
            'lastSync' => $this->intIn(1, 2880, 'mdm-ls|' . $i) . ' min ago',
            'enrolled' => $this->dayBack($this->intIn(30, 900, 'mdm-en|' . $i)),
            'encrypted' => ($this->h('mdm-enc|' . $i) % 10 === 0) ? 'No' : 'Yes',
        ];
    }

    public function mdmDeviceById(string $slug): array
    {
        $i = $this->indexFromNumericTail($slug, 20001, $this->mdmCount());
        if ($i !== null) {
            return $this->mdmDeviceAt($i);
        }
        return $this->mdmDeviceAt($this->h('synmdm|' . $slug) % $this->mdmCount());
    }

    /**
     * Fleet compliance headline counts (compliant + at-risk + non-compliant = enrolled, by construction
     * over a bounded scan), so the MDM landing tiles reconcile with the fleet.
     *
     * @return array{enrolled:int,compliant:int,atRisk:int,nonCompliant:int}
     */
    public function mdmSummary(): array
    {
        $total = $this->mdmCount();
        $scan = $total < 400 ? $total : 400;         // bound the scan; ratios hold, tiles stay honest
        $compliant = 0;
        $atRisk = 0;
        for ($i = 0; $i < $scan; $i++) {
            $c = $this->mdmDeviceAt($i)['compliance'];
            if ($c === 'Compliant') {
                $compliant++;
            } elseif ($c === 'At risk') {
                $atRisk++;
            }
        }
        // Scale the sample up to the full fleet so the three buckets still sum to enrolled.
        $compliant = (int) round($compliant / $scan * $total);
        $atRisk = (int) round($atRisk / $scan * $total);
        $nonCompliant = $total - $compliant - $atRisk;
        if ($nonCompliant < 0) {
            $nonCompliant = 0;
            $compliant = $total - $atRisk;
        }
        return [
            'enrolled' => $total,
            'compliant' => $compliant,
            'atRisk' => $atRisk,
            'nonCompliant' => $nonCompliant,
        ];
    }

    // =====================================================================
    // Mail admin
    // =====================================================================

    /** One mailbox per employee (mailboxes ~= N) so the count reconciles with the roster (spec E3). */
    public function mailboxCount(): int
    {
        return $this->org->magnitudes()['mailboxes'];
    }

    /** @return list<array> */
    public function mailboxPage(int $offset, int $limit): array
    {
        return $this->page($this->mailboxCount(), $offset, $limit, 'mailboxAt');
    }

    /**
     * One mailbox by 0-based index — the i-th Org employee, at the host's one domain. Quota used never
     * exceeds quota total. At most ONE budgeted mailbox carries a suspicious EXTERNAL forwarding rule
     * (the deliberate anomaly): its target is a clearly-fake reserved (.example) domain, never a real one.
     *
     * @return array{index:int,id:string,address:string,displayName:string,dept:string,quotaUsedMb:int,quotaTotalMb:int,lastSignIn:string,forwarding:list<array{to:string,scope:string,suspicious:bool}>}
     */
    public function mailboxAt(int $i): array
    {
        $n = $this->org->headcount();
        $person = $this->org->people($n)[$i % $n];
        $total = $this->pickInt([5120, 10240, 51200, 102400], 'mb-qt|' . $i);
        $used = $this->intIn((int) round($total * 0.1), (int) round($total * 0.98), 'mb-qu|' . $i);

        $forwarding = [];
        // A small minority forward internally (benign). Exactly one seeded mailbox forwards externally.
        if ($this->h('mb-fwd|' . $i) % 12 === 0) {
            $mgrId = $person['managerId'] !== '' ? $person['managerId'] : $person['id'];
            $mgr = $this->org->person($mgrId);
            $to = $mgr !== null ? $mgr['email'] : $person['email'];
            $forwarding[] = ['to' => $to, 'scope' => 'Internal — copy on delivery', 'suspicious' => false];
        }
        if ($i === $this->suspiciousMailboxIndex()) {
            $forwarding[] = [
                'to' => 'archive.sync' . sprintf('%03d', $this->h('mb-ext|' . $i) % 1000) . '@mailbackup-secure.example',
                'scope' => 'External — forward and delete local copy',
                'suspicious' => true,
            ];
        }

        return [
            'index' => $i,
            'id' => 'mbx-' . sprintf('%04d', 1001 + $i),
            'address' => $person['email'],
            'displayName' => $person['name'],
            'dept' => $person['dept'],
            'quotaUsedMb' => $used,
            'quotaTotalMb' => $total,
            'lastSignIn' => $this->dayBack($this->intIn(0, 30, 'mb-ls|' . $i)),
            'forwarding' => $forwarding,
        ];
    }

    public function mailboxById(string $slug): array
    {
        $i = $this->indexFromNumericTail($slug, 1001, $this->mailboxCount());
        if ($i !== null) {
            return $this->mailboxAt($i);
        }
        return $this->mailboxAt($this->h('synmbx|' . $slug) % $this->mailboxCount());
    }

    /** The one mailbox index carrying the budgeted suspicious external forwarding rule (spec E2). */
    public function suspiciousMailboxIndex(): int
    {
        return $this->h('mb-suspect') % $this->mailboxCount();
    }

    // =====================================================================
    // Certificates
    // =====================================================================

    public function certCount(): int
    {
        return $this->intIn(18, 60, 'certcount');
    }

    /** @return list<array> */
    public function certPage(int $offset, int $limit): array
    {
        return $this->page($this->certCount(), $offset, $limit, 'certAt');
    }

    /**
     * One certificate by 0-based index. The subject/SANs render at the host's one domain; the expiry is a
     * frozen-clock date (a couple in the corpus are budgeted to be near/past expiry). The fingerprint and
     * serial are fabricated hex; private material is never generated (downloads are inert decoys).
     *
     * @return array{index:int,id:string,subject:string,issuer:string,serial:string,keyType:string,notBefore:string,notAfter:string,daysLeft:int,fingerprint:string,sans:list<string>,status:string}
     */
    public function certAt(int $i): array
    {
        $host = $this->pick(['mail', 'vpn', 'portal', 'intranet', 'api', 'wildcard', 'sso', 'files'], 'cert-h|' . $i);
        $subject = $host === 'wildcard' ? '*.' . $this->domain : $host . '.' . $this->domain;

        // Most certs are valid for months; a budgeted 0-2 sit near/after expiry (spec E2).
        $expiring = ($i % 17 === 3) || ($i % 23 === 7);
        if ($expiring) {
            $daysLeft = $this->intIn(-12, 21, 'cert-exp|' . $i);
        } else {
            $daysLeft = $this->intIn(45, 800, 'cert-exp|' . $i);
        }
        $issuedBack = $this->intIn(60, 365, 'cert-ib|' . $i);
        $status = $daysLeft < 0 ? 'Expired' : ($daysLeft <= 21 ? 'Expiring soon' : 'Valid');

        $sans = [$subject];
        if ($host !== 'wildcard') {
            $sans[] = $host . '-dr.' . $this->domain;
        }

        return [
            'index' => $i,
            'id' => 'cert-' . sprintf('%04d', 1001 + $i),
            'subject' => $subject,
            'issuer' => $this->pick(
                ['Corevance Enterprise CA', 'Internal Issuing CA 01', 'Meridian Root CA', 'Northgate PKI', 'SecureTrust DV CA'],
                'cert-iss|' . $i
            ),
            'serial' => $this->hexColon(8, 'cert-sn|' . $i),
            'keyType' => $this->pick(['RSA 2048', 'RSA 4096', 'EC P-256'], 'cert-kt|' . $i),
            'notBefore' => $this->dayBack($issuedBack),
            'notAfter' => $daysLeft >= 0 ? $this->dayAhead($daysLeft) : $this->dayBack(-$daysLeft),
            'daysLeft' => $daysLeft,
            'fingerprint' => $this->hexColon(32, 'cert-fp|' . $i),
            'sans' => $sans,
            'status' => $status,
        ];
    }

    public function certById(string $slug): array
    {
        $i = $this->indexFromNumericTail($slug, 1001, $this->certCount());
        if ($i !== null) {
            return $this->certAt($i);
        }
        return $this->certAt($this->h('syncert|' . $slug) % $this->certCount());
    }

    // --- small shared helpers ---

    /**
     * One page of a corpus by absolute offset, calling $method (a public generator on this class) per row.
     *
     * @return list<array>
     */
    private function page(int $total, int $offset, int $limit, string $method): array
    {
        if ($offset < 0) {
            $offset = 0;
        }
        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            if ($i >= $total) {
                break;
            }
            $out[] = $this->{$method}($i);
        }
        return $out;
    }

    /**
     * Recover a 0-based index from an id whose trailing numeric group is `$base + index` (printer ids
     * count from 1, mailbox/licence/cert from 1001, MDM from 20001). Returns null when there is no
     * in-range numeric tail, so the caller can fall back to a synthetic-but-plausible row rather than
     * dead-ending (a 404 inside the panel is a tell).
     */
    private function indexFromNumericTail(string $slug, int $base, int $total): ?int
    {
        if (preg_match('/(\d+)$/', $slug, $m) !== 1) {
            return null;
        }
        $i = ((int) $m[1]) - $base;
        if ($i < 0 || $i >= $total) {
            return null;
        }
        return $i;
    }
}
