<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT vendor / supplier ledger for the deep office panel — the business-email-compromise
 * (BEC) bait surface (spec §C.6). It is a VIEW that reuses the `Org` roster for the internal relationship
 * owner of each vendor (name + email at the host persona domain), and grows its own reconciling invoice
 * corpus per vendor so a vendor's spend history, linked invoices, open balance and aging always add up.
 *
 * Design rules (deep-admin dashboard spec §C.6 + §E + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); a static reload is byte-identical (a diffable page is a tell).
 *  - ARITHMETIC CLOSES (integer cents, exact): per invoice, subtotal + tax = total and paid + balance =
 *    total; per vendor, YTD spend = Sum(paid) and open balance = Sum(balance); the aging buckets of an
 *    open balance sum back to that open balance. An attacker who totals it up finds it consistent.
 *  - SAFE: every vendor, contact, tax id and remit-to bank detail is fabricated and INVALID-FORMAT —
 *    account/IBAN masked with invalid check digits, tax ids masked, phones in the reserved 555-01xx
 *    fictional range. No real bank name/BIN that resolves, no real trademark, no scanner-signature string.
 *  - ONE DOMAIN: the only email a vendor row renders is its INTERNAL owner's, at the host persona domain
 *    (one host = one domain). External vendor-side contacts carry a name + phone only, never an email at
 *    an invented second domain.
 *  - ANOMALY BUDGET: hash(seed) plants 0-2 vendor anomalies (a recent bank-change flag, an on-hold
 *    vendor); most render clean — a buffet of honeytokens reads as staged.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/intdiv, no enums/promotion/str_contains) so a fact can
 *    promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Vendors
{
    /** @var int */
    private $seed;

    /** @var string the host persona domain the internal owner's email renders at. */
    private $personaDomain;

    /** @var Org */
    private $org;

    /** @var array<string,array>|null cached per-vendor aggregates (spend/open/aging) keyed by vendor id */
    private $aggCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->personaDomain = $personaDomain;
        $this->org = Org::fromSeed($seed, $personaDomain);
    }

    /**
     * Build the vendor ledger for a seed. The section MUST pass the host persona domain so the internal
     * owner emails never contradict the one domain shown elsewhere on the host.
     */
    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|vnd|' . $salt), 0, 15));
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

    /** Terms string -> net days (Due on receipt = 0); drives due-date arithmetic off the invoice date. */
    private function termsDays(string $vendorId): int
    {
        $map = ['Net 15' => 15, 'Net 30' => 30, 'Net 45' => 45, 'Net 60' => 60, 'Due on receipt' => 0];
        $terms = $this->pick(['Net 15', 'Net 30', 'Net 45', 'Net 60', 'Due on receipt'], 'terms|' . $vendorId);
        return $map[$terms];
    }

    // --- magnitude (scales off the one Org headcount so nothing contradicts) ---

    /** Vendor count, derived from headcount so a 200-person company never shows 50,000 suppliers. */
    public function vendorCount(): int
    {
        $n = $this->org->headcount();
        return (int) round($n * 0.6) + 20;                   // ~74..182 for N 90..270
    }

    // --- vendor list (paginated) ---

    /**
     * One page of the vendor list by absolute offset, so a deep page renders identically and instantly.
     * Each row carries the aggregates (spend YTD, open balance) computed from that vendor's invoice corpus,
     * so the list and the detail can never disagree.
     *
     * @return list<array{id:string,name:string,category:string,status:string,owner:string,ownerEmail:string,terms:string,spendYtd:int,openBalance:int,invoiceCount:int,lastInvoice:string,bankChanged:bool}>
     */
    public function vendorsPage(int $offset, int $limit): array
    {
        $total = $this->vendorCount();
        if ($offset < 0) {
            $offset = 0;
        }
        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            if ($i >= $total) {
                break;
            }
            $out[] = $this->vendorAt($i);
        }
        return $out;
    }

    /** One vendor row by 0-based index (< vendorCount). */
    private function vendorAt(int $i): array
    {
        return $this->vendorRecord($this->idFor($i), $i);
    }

    private function idFor(int $i): string
    {
        return 'vendor-' . sprintf('%04d', 1001 + $i);
    }

    /** vendor-#### -> 0-based index, or null when the id is outside the ledger. */
    private function indexOfId(string $id): ?int
    {
        if (strpos($id, 'vendor-') !== 0) {
            return null;
        }
        $num = substr($id, 7);
        if ($num === '' || !ctype_digit($num)) {
            return null;
        }
        $i = ((int) $num) - 1001;
        if ($i < 0 || $i >= $this->vendorCount()) {
            return null;
        }
        return $i;
    }

    /**
     * One vendor by id. A known id returns its exact list row; an unknown/fuzzed slug returns a plausible
     * seeded vendor (keyed by the slug) so a crawl never falls off the edge (a 404 inside the panel is a
     * tell). Either way the invoice corpus keys off the id string, so the detail's arithmetic still closes.
     */
    public function vendor(string $id): array
    {
        $i = $this->indexOfId($id);
        if ($i !== null) {
            return $this->vendorAt($i);
        }
        // Synthetic vendor from a fuzzed slug: derive a stable pseudo-index for name/category vocab.
        return $this->vendorRecord($id, $this->h('synidx|' . $id) % 9973);
    }

    /** Build a full vendor record from its id (facts) and an index (vocab spread). Pure per (seed,id,i). */
    private function vendorRecord(string $id, int $i): array
    {
        $name = $this->companyName($id, $i);
        $ownerIdx = $this->h('owner|' . $id) % $this->org->headcount();
        $owner = $this->org->people($this->org->headcount())[$ownerIdx];
        $agg = $this->aggregatesFor($id);

        $status = $this->statusFor($id);
        return [
            'id' => $id,
            'name' => $name,
            'category' => $this->pick(
                ['IT Hardware', 'SaaS / Software', 'Facilities & FM', 'Professional Services', 'Logistics',
                 'Office Supplies', 'Marketing Agency', 'Cleaning Services', 'Catering', 'Security Services',
                 'Print & Signage', 'Telecoms', 'Utilities', 'Recruitment', 'Legal'],
                'cat|' . $id
            ),
            'status' => $status,
            'owner' => $owner['name'],
            'ownerEmail' => $owner['email'],                 // internal AP owner, at the one host domain
            'terms' => $this->pick(['Net 15', 'Net 30', 'Net 45', 'Net 60', 'Due on receipt'], 'terms|' . $id),
            'spendYtd' => $agg['spendYtd'],
            'openBalance' => $agg['openBalance'],
            'invoiceCount' => $agg['invoiceCount'],
            'lastInvoice' => $agg['lastInvoice'],
            'bankChanged' => $this->bankChangedFlag($id),
        ];
    }

    /** Company name — invented adjective/noun + legal suffix combinator, never a real trademark. */
    private function companyName(string $id, int $i): string
    {
        $stem = [
            'Northgate', 'Sterling', 'Harborline', 'Cedar Ridge', 'Ironbridge', 'Lakeside', 'Bluestone',
            'Redwood', 'Summit', 'Vantage', 'Clearwater', 'Granite', 'Beacon', 'Kestrel', 'Foundry',
            'Meridian Vale', 'Ashford', 'Copperfield', 'Windrow', 'Northwind', 'Silverpeak', 'Oakline',
        ];
        $trade = [
            'Systems', 'Logistics', 'Supplies', 'Partners', 'Industrial', 'Services', 'Solutions',
            'Technologies', 'Facilities', 'Print', 'Distribution', 'Group', 'Networks', 'Associates',
        ];
        $suffix = ['LLC', 'Ltd', 'Inc', 'Co', 'Holdings'];
        $s = $stem[$i % count($stem)];
        $t = $this->pick($trade, 'trade|' . $id);
        $x = $this->pick($suffix, 'suffix|' . $id);
        return $s . ' ' . $t . ' ' . $x;
    }

    /** Mostly Active; a small budgeted minority On hold / Pending review (never a buffet). */
    private function statusFor(string $id): string
    {
        $r = $this->h('status|' . $id) % 100;
        if ($r < 88) {
            return 'Active';
        }
        if ($r < 96) {
            return 'Pending review';
        }
        return 'On hold';
    }

    /**
     * The planted "vendor bank details recently changed" flag — the in-progress-fraud bait. A true 0-2
     * budget for the WHOLE ledger (not a per-vendor probability): the seed picks a count 0-2 and the one
     * or two specific vendor indices that carry it, so the honeytoken never turns into a buffet. Synthetic
     * (off-ledger) ids never carry it.
     */
    private function bankChangedFlag(string $id): bool
    {
        $idx = $this->indexOfId($id);
        if ($idx === null) {
            return false;
        }
        $count = $this->h('bankchg-count') % 3;              // 0, 1 or 2 flagged vendors
        if ($count >= 1 && $idx === $this->h('bankchg-1') % $this->vendorCount()) {
            return true;
        }
        if ($count >= 2 && $idx === $this->h('bankchg-2') % $this->vendorCount()) {
            return true;
        }
        return false;
    }

    // --- invoices (self-contained, reconciling) ---

    /**
     * The invoice corpus for one vendor. Every amount is integer cents so the arithmetic is exact:
     * subtotal + tax = total, paid + balance = total. Keyed off the vendor id string so a known and a
     * synthetic vendor both produce a coherent, stable set.
     *
     * @return list<array{routeId:string,display:string,date:string,due:string,po:string,lines:list<array{desc:string,qty:int,unitCents:int,amountCents:int}>,subtotalCents:int,taxRate:int,taxCents:int,totalCents:int,paidCents:int,balanceCents:int,status:string,daysPastDue:int}>
     */
    public function invoicesFor(string $vendorId): array
    {
        $count = 3 + ($this->h('invn|' . $vendorId) % 10);   // 3..12
        $out = [];
        for ($k = 0; $k < $count; $k++) {
            $out[] = $this->invoiceAt($vendorId, $k);
        }
        return $out;
    }

    private function invoiceAt(string $vendorId, int $k): array
    {
        $salt = $vendorId . '|inv|' . $k;
        // Vendor-side invoice numbers live in a HIGH band (>=100000) that never overlaps Finance's AP
        // corpus (INV-<year>-004001..), so one number can never resolve to two different invoices.
        $num = 100000 + ($this->h($salt . '|num') % 800000);   // 100000..899999
        $routeId = 'inv-' . FrozenClock::year() . '-' . sprintf('%06d', $num);
        $display = 'INV-' . FrozenClock::year() . '-' . sprintf('%06d', $num);

        $lineCount = 1 + ($this->h($salt . '|lc') % 4);      // 1..4 lines
        $descVocab = [
            'Managed service — monthly', 'Hardware — bulk order', 'Professional services — hours',
            'Software subscription (annual)', 'Consumables & supplies', 'On-site maintenance visit',
            'Licence renewal', 'Freight & handling', 'Installation labour', 'Support retainer',
        ];
        $lines = [];
        $subtotal = 0;
        for ($l = 0; $l < $lineCount; $l++) {
            $lsalt = $salt . '|l' . $l;
            $qty = 1 + ($this->h($lsalt . '|q') % 12);
            $unit = (5 + ($this->h($lsalt . '|u') % 495)) * 100 + ($this->h($lsalt . '|c') % 100);
            $amount = $qty * $unit;
            $subtotal += $amount;
            $lines[] = [
                'desc' => $descVocab[$this->h($lsalt . '|d') % count($descVocab)],
                'qty' => $qty,
                'unitCents' => $unit,
                'amountCents' => $amount,
            ];
        }

        $rate = (int) $this->pick(['0', '5', '10', '20'], $salt . '|rate');
        $tax = intdiv($subtotal * $rate, 100);               // exact integer cents
        $total = $subtotal + $tax;

        // Dates close: invoice date is within ~200 days of the frozen "now"; the due date is the invoice
        // date plus the vendor's own payment terms (so due >= date always); daysPastDue is "now − due"
        // measured off the same clock (negative when the invoice is not yet due).
        $ageDays = $this->h($salt . '|age') % 201;            // 0..200 days ago
        $dateEpoch = FrozenClock::epoch() - $ageDays * 86400;
        $dueEpoch = $dateEpoch + $this->termsDays($vendorId) * 86400;
        $daysPastDue = FrozenClock::nowDays() - intdiv($dueEpoch, 86400);

        // Payment state — paid + balance always equals total. Overdue only when unpaid AND past due.
        $roll = $this->h($salt . '|pay') % 100;
        if ($roll < 55) {
            $paid = $total;
            $balance = 0;
            $status = 'Paid';
        } elseif ($roll < 70) {
            $pct = 10 + ($this->h($salt . '|ppct') % 80);    // 10..89 %
            $paid = intdiv($total * $pct, 100);
            $balance = $total - $paid;
            $status = 'Partial';
        } else {
            $paid = 0;
            $balance = $total;
            $status = $daysPastDue > 0 ? 'Overdue' : 'Open';
        }

        return [
            'routeId' => $routeId,
            'display' => $display,
            'date' => FrozenClock::ymd($dateEpoch),
            'due' => FrozenClock::ymd($dueEpoch),
            'po' => 'PO-' . FrozenClock::year() . '-' . sprintf('%05d', 100 + ($this->h($salt . '|po') % 89000)),
            'lines' => $lines,
            'subtotalCents' => $subtotal,
            'taxRate' => $rate,
            'taxCents' => $tax,
            'totalCents' => $total,
            'paidCents' => $paid,
            'balanceCents' => $balance,
            'status' => $status,
            'daysPastDue' => $daysPastDue,
        ];
    }

    /** One invoice by its route id for a vendor; a plausible seeded invoice when the id is unknown. */
    public function invoice(string $vendorId, string $invoiceRouteId): array
    {
        foreach ($this->invoicesFor($vendorId) as $inv) {
            if ($inv['routeId'] === $invoiceRouteId) {
                return $inv;
            }
        }
        // Unknown/fuzzed invoice slug — synthesise a stable plausible one so the crawl never dead-ends.
        return $this->invoiceAt($vendorId . '|syn|' . $invoiceRouteId, 0);
    }

    // --- per-vendor aggregates (derived from invoicesFor, so they always agree) ---

    /**
     * Spend YTD (Sum paid), open balance (Sum balance) and the aging breakdown of that open balance for a
     * vendor. Because every figure is summed from the same invoice corpus, the aging buckets add back to
     * the open balance and the row/detail totals can never diverge.
     *
     * @return array{spendYtd:int,openBalance:int,invoiceCount:int,lastInvoice:string,aging:array<string,int>}
     */
    public function aggregatesFor(string $vendorId): array
    {
        if ($this->aggCache === null) {
            $this->aggCache = [];
        }
        if (isset($this->aggCache[$vendorId])) {
            return $this->aggCache[$vendorId];
        }
        $invoices = $this->invoicesFor($vendorId);
        $spend = 0;
        $open = 0;
        $aging = [
            'Current' => 0,
            '1–30 days' => 0,
            '31–60 days' => 0,
            '61–90 days' => 0,
            '90+ days' => 0,
        ];
        $last = '';
        foreach ($invoices as $inv) {
            $spend += $inv['paidCents'];
            if ($inv['balanceCents'] > 0) {
                $open += $inv['balanceCents'];
                $aging[$this->agingBucket($inv['daysPastDue'])] += $inv['balanceCents'];
            }
            if ($inv['date'] > $last) {
                $last = $inv['date'];
            }
        }
        $agg = [
            'spendYtd' => $spend,
            'openBalance' => $open,
            'invoiceCount' => count($invoices),
            'lastInvoice' => $last,
            'aging' => $aging,
        ];
        $this->aggCache[$vendorId] = $agg;
        return $agg;
    }

    private function agingBucket(int $days): string
    {
        if ($days <= 0) {
            return 'Current';
        }
        if ($days <= 30) {
            return '1–30 days';
        }
        if ($days <= 60) {
            return '31–60 days';
        }
        if ($days <= 90) {
            return '61–90 days';
        }
        return '90+ days';
    }

    // --- ledger-wide summary (aggregated over every vendor, so tiles reconcile to the list) ---

    /**
     * Headline figures for the landing stat tiles, summed across the whole ledger so the totals reconcile
     * to what a full walk of the list would add up to.
     *
     * @return array{total:int,active:int,onHold:int,pendingReview:int,spendYtdCents:int,openPayablesCents:int,bankChanges:int}
     */
    public function summary(): array
    {
        $total = $this->vendorCount();
        $active = 0;
        $onHold = 0;
        $pending = 0;
        $spend = 0;
        $open = 0;
        $bankChanges = 0;
        for ($i = 0; $i < $total; $i++) {
            $v = $this->vendorAt($i);
            if ($v['status'] === 'Active') {
                $active++;
            } elseif ($v['status'] === 'On hold') {
                $onHold++;
            } else {
                $pending++;
            }
            $spend += $v['spendYtd'];
            $open += $v['openBalance'];
            if ($v['bankChanged']) {
                $bankChanges++;
            }
        }
        return [
            'total' => $total,
            'active' => $active,
            'onHold' => $onHold,
            'pendingReview' => $pending,
            'spendYtdCents' => $spend,
            'openPayablesCents' => $open,
            'bankChanges' => $bankChanges,
        ];
    }

    // --- contact + remit-to (all fabricated + invalid-format) ---

    /**
     * The external vendor-side contact: a fabricated name + fictional-range phone only — NEVER an email at
     * an invented second domain (one host = one domain). @return array{0:string,1:string} [name, phone]
     */
    public function contactFor(string $vendorId): array
    {
        $fore = $this->pick(
            ['Sam', 'Alex', 'Jordan', 'Robin', 'Casey', 'Drew', 'Morgan', 'Taylor', 'Jamie', 'Riley'],
            'cfore|' . $vendorId
        );
        $sur = $this->pick(
            ['Hart', 'Ford', 'Beck', 'Cole', 'Frost', 'Nash', 'Reed', 'Payne', 'Boyd', 'Vance'],
            'csur|' . $vendorId
        );
        // 555-01xx is the reserved fictional exchange — a phone that can never dial a real line.
        $phone = sprintf('+1 (555) 01%02d-%04d',
            $this->intIn(0, 99, 'ph1|' . $vendorId),
            $this->intIn(0, 9999, 'ph2|' . $vendorId));
        return [$fore . ' ' . $sur, $phone];
    }

    /**
     * The masked, invalid-format remit-to bank details — the AP jackpot the attacker screenshots and the
     * BEC target. Bank name is invented (no real BIN); the IBAN carries the always-invalid "00" check
     * digits; account/sort/SWIFT are shown as masked tails only, so nothing here can validate or transact.
     *
     * @return array{bank:string,accountMasked:string,ibanMasked:string,sortMasked:string,swiftMasked:string,taxIdMasked:string}
     */
    public function remitToFor(string $vendorId): array
    {
        $bankStem = $this->pick(
            ['Northgate', 'Sterling', 'Harborline', 'Cedar Ridge', 'Ironbridge', 'Lakeside', 'Bluestone', 'Granite'],
            'bankstem|' . $vendorId
        );
        $bankKind = $this->pick(
            ['Commercial Bank', 'Mercantile Bank', 'Business Bank', 'Savings & Trust', 'Credit Union'],
            'bankkind|' . $vendorId
        );
        $last4 = sprintf('%04d', $this->intIn(0, 9999, 'acct|' . $vendorId));
        $ibanCc = $this->pick(['GB', 'IE', 'DE', 'FR', 'NL'], 'ibancc|' . $vendorId);
        $ibanLast2 = sprintf('%02d', $this->intIn(0, 99, 'iban2|' . $vendorId));
        $sortLast2 = sprintf('%02d', $this->intIn(0, 99, 'sort|' . $vendorId));
        // Four uppercase letters + masked tail — a masked stand-in for a BIC, never a resolvable one.
        $swiftHead = strtoupper(substr(preg_replace('/[^a-z]/', 'x', hash('sha256', $this->seed . '|swift|' . $vendorId)), 0, 4));
        // EIN-shaped tax id, masked to a non-validating tail.
        $taxTail = sprintf('%04d', $this->intIn(0, 9999, 'tax|' . $vendorId));

        return [
            'bank' => $bankStem . ' ' . $bankKind,
            'accountMasked' => '••••••' . $last4,
            'ibanMasked' => $ibanCc . '00 •••• •••• •••• ••' . $ibanLast2,   // "00" check digits => invalid IBAN
            'sortMasked' => '••-••-' . $sortLast2,
            'swiftMasked' => $swiftHead . '••XX•••',
            'taxIdMasked' => '**-***' . $taxTail,
        ];
    }
}
