<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT finance estate for the deep office panel — the greed lure (spec §C.6). It is a
 * VIEW over the `Org` roster (approvers/actors are real employees at the host's one domain) plus its own
 * fabricated vendor book, invoice/expense corpora and audit trail. Nothing here is or implies real money
 * movement; the section renders soft-denials on every money verb.
 *
 * Design rules (deep-admin dashboard spec §C.6 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); every clock/date string is formatted by integer arithmetic off one
 *    frozen DEPLOY_EPOCH, so a static reload is byte-identical and never a tell.
 *  - ARITHMETIC CLOSES: an invoice's line items sum to its subtotal, subtotal + tax - discount = total,
 *    paid <= total, balance = total - paid; a dashboard's aging buckets sum to AP outstanding; an
 *    expense report's lines sum to its total. An attacker who adds it up finds it consistent.
 *  - SAFE: all money is fabricated; bank/remit detail is masked at rest and structurally INVALID on
 *    reveal (no real bank name/BIN, no validating IBAN/account/card). Actor IPs are the employee VLAN
 *    (10.0.20.x via Org), RFC1918 only. No real trademark, no scanner-signature string.
 *  - ONE DOMAIN: approver/actor emails render at the host persona domain (passed in), never a second
 *    invented domain — one host = one domain.
 *  - ANOMALY BUDGET: hash(seed) plants at most one audit anomaly (a vendor bank-detail change by an
 *    unusual actor — the in-progress-fraud bait); most rows read clean.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/promotion/str_contains/arrow fns)
 *    so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it. Money is carried in integer cents
 * so sums are exact; money() formats for display.
 */
final class Finance
{
    /** Frozen "now" for dates/ages so a static reload is not a tell — the one shared clock (2026-08-24). */
    public const DEPLOY_EPOCH = FrozenClock::EPOCH;

    private const FY = '2026';

    /** First document index -> invoice/PO/expense numbers, so an id maps back to a corpus index. */
    private const INV_BASE = 4001;
    private const EXP_BASE = 2001;

    /** @var int */
    private $seed;

    /** @var string host persona domain — approver/actor emails render here (one host = one domain). */
    private $domain;

    /** @var Org */
    private $org;

    /** @var Vendors the one vendor book; Finance's vendor/remit/invoice data is a view over it. */
    private $vendors;

    private function __construct(int $seed, string $domain)
    {
        $this->seed = $seed;
        $this->domain = $domain;
        $this->org = Org::fromSeed($seed, $domain);
        $this->vendors = Vendors::fromSeed($seed, $domain);
    }

    public static function fromSeed(int $seed, string $domain = ''): self
    {
        return new self($seed, $domain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|fin|' . $salt), 0, 15));
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

    /** YYYY-MM-DD for an absolute epoch, from the one shared clock (integer arithmetic; no date()). */
    private function ymd(int $epoch): string
    {
        return FrozenClock::ymd($epoch);
    }

    /** '$1,234.56' from integer cents — the one display formatter (sums stay in cents, exact). */
    public function money(int $cents): string
    {
        $neg = $cents < 0;
        $abs = $neg ? -$cents : $cents;
        return ($neg ? '-$' : '$') . number_format($abs / 100, 2);
    }

    // --- fiscal identity + dashboard (aging buckets sum to AP outstanding) ---

    public function fiscalYear(): string
    {
        return self::FY;
    }

    public function currency(): string
    {
        return 'USD';
    }

    /** The frozen "as of" date the dashboard/audit reference. */
    public function asOf(): string
    {
        return $this->ymd(self::DEPLOY_EPOCH);
    }

    /**
     * The standing second approver every money verb routes to — a real roster member at the host domain,
     * so the four-eyes / dual-approval wall names someone who exists in the directory but who the attacker
     * can never act as. Deterministic per seed.
     *
     * @return array{name:string,email:string,title:string}
     */
    public function secondApprover(): array
    {
        $roster = $this->org->people($this->org->headcount());
        // Pick the senior signer by BAND (first executive/M5), the same rule Payroll uses, and carry that
        // person's ACTUAL directory title — so the four-eyes wall never names a title HR contradicts.
        $p = $roster[0];
        foreach ($roster as $candidate) {
            if ($candidate['band'] === 'M5') {
                $p = $candidate;
                break;
            }
        }
        return ['name' => $p['name'], 'email' => $p['email'], 'title' => $p['title']];
    }

    /**
     * Company-level finance figures for the dashboard stat tiles. AP outstanding is the sum of the aging
     * buckets by construction; overdue is the sum of the three past-due buckets — both close exactly.
     *
     * @return array{cashOnHand:int,apOutstanding:int,arOutstanding:int,overdue:int,invoicesOpen:int,aging:list<array{0:string,1:int}>}
     */
    public function dashboard(): array
    {
        $current = $this->intIn(80000, 1400000, 'age-current') * 100;   // cents
        $d1 = $this->intIn(40000, 900000, 'age-1-30') * 100;
        $d2 = $this->intIn(10000, 400000, 'age-31-60') * 100;
        $d3 = $this->intIn(4000, 180000, 'age-61-90') * 100;
        $d4 = $this->intIn(1000, 90000, 'age-90') * 100;
        $ap = $current + $d1 + $d2 + $d3 + $d4;
        return [
            // Cash on hand is NOT seeded here — it is the treasury total (Σ bank balances) so the finance
            // dashboard and the bank landing show one and the same figure on the one host.
            'cashOnHand' => Bank::fromSeed($this->seed, $this->domain)->summary()['cashOnHand'],
            'apOutstanding' => $ap,
            'arOutstanding' => $this->intIn(300000, 12000000, 'ar') * 100,
            'overdue' => $d2 + $d3 + $d4,
            // Read off the SAME per-invoice status decision invoiceAt() uses (not a second independent
            // seed), so this tile can never drift from what the invoice list itself shows.
            'invoicesOpen' => $this->openInvoiceCount(),
            'aging' => [
                ['Current', $current],
                ['1–30 days', $d1],
                ['31–60 days', $d2],
                ['61–90 days', $d3],
                ['90+ days', $d4],
            ],
        ];
    }

    // --- vendors (the fabricated vendor book) ---

    public function vendorCount(): int
    {
        return $this->vendors->vendorCount();
    }

    /**
     * One vendor by 0-based index — a VIEW over the one `Fake\Vendors` book, so a vendor named on the AP
     * ledger (id, name, category, remit-to) resolves to the exact same record under /panel/vendors. Remit
     * detail is masked at rest and non-validating (invalid-format account / sort / IBAN), so nothing an
     * attacker copies out will validate against a real bank.
     *
     * @return array{id:string,name:string,category:string,contact:string,bankName:string,acctMasked:string,sortMasked:string,ibanMasked:string,ytdSpend:int}
     */
    public function vendorAt(int $i): array
    {
        $id = 'vendor-' . sprintf('%04d', 1001 + $i);
        $v = $this->vendors->vendor($id);
        $remit = $this->vendors->remitToFor($id);
        $contact = $this->vendors->contactFor($id);

        return [
            'id' => $v['id'],
            'name' => $v['name'],
            'category' => $v['category'],
            'contact' => $contact[0],
            'bankName' => $remit['bank'],
            'acctMasked' => $remit['accountMasked'],
            'sortMasked' => $remit['sortMasked'],
            'ibanMasked' => $remit['ibanMasked'],
            'ytdSpend' => $v['spendYtd'],
        ];
    }

    // --- invoice corpus (Accounts Payable) ---

    /** A large, seeded corpus size so paginated enumeration is effectively bottomless but deterministic. */
    public function invoiceCount(): int
    {
        return $this->intIn(4200, 9800, 'invcount');
    }

    /**
     * One page of invoices by absolute offset, so page 80 renders identically and instantly.
     *
     * @return list<array> each element is a full invoiceAt() record
     */
    public function invoicePage(int $offset, int $limit): array
    {
        $total = $this->invoiceCount();
        if ($offset < 0) {
            $offset = 0;
        }
        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            if ($i >= $total) {
                break;
            }
            $out[] = $this->invoiceAt($i);
        }
        return $out;
    }

    /**
     * One fully-reconciled invoice by 0-based corpus index. Line items sum to subtotal; subtotal + tax -
     * discount = total; paid is 0 or the full total (so paid <= total always); balance = total - paid.
     *
     * @return array{index:int,number:string,id:string,vendorName:string,vendorId:string,po:string,invoiceDate:string,dueDate:string,lines:list<array{desc:string,qty:int,unitCents:int,lineCents:int}>,subtotalCents:int,taxRateBp:int,taxCents:int,discountCents:int,totalCents:int,paidCents:int,balanceCents:int,status:string,approver:string,approverEmail:string,currency:string}
     */
    public function invoiceAt(int $i): array
    {
        $vendor = $this->vendorAt($this->h('inv-vendor|' . $i) % $this->vendorCount());

        $descVocab = [
            'Professional services', 'Monthly SaaS subscription', 'Hardware — rack units',
            'Cleaning services', 'Courier & freight', 'Printed materials', 'Catering — offsite',
            'Consulting — statement of work', 'Maintenance contract', 'Office supplies',
            'Security patrol hours', 'Software licences', 'Network cabling', 'Temporary staffing',
        ];
        $lineCount = $this->intIn(2, 6, 'inv-lc|' . $i);
        $lines = [];
        $subtotal = 0;
        for ($k = 0; $k < $lineCount; $k++) {
            $qty = $this->intIn(1, 40, 'inv-q|' . $i . '|' . $k);
            $unit = $this->intIn(1500, 250000, 'inv-u|' . $i . '|' . $k); // cents
            $lineTotal = $qty * $unit;
            $subtotal += $lineTotal;
            $lines[] = [
                'desc' => $descVocab[$this->h('inv-d|' . $i . '|' . $k) % count($descVocab)],
                'qty' => $qty,
                'unitCents' => $unit,
                'lineCents' => $lineTotal,
            ];
        }

        $rateBp = $this->pickInt([0, 1000, 2000, 2300], 'inv-tax|' . $i);   // 0 / 10 / 20 / 23 %
        $tax = intdiv($subtotal * $rateBp, 10000);
        $discount = ($this->h('inv-disc|' . $i) % 4 === 0)
            ? intdiv($subtotal, $this->intIn(20, 50, 'inv-dr|' . $i))       // occasional small discount
            : 0;
        $total = $subtotal + $tax - $discount;

        $st = $this->invoiceStatusAt($i);
        $status = $st['status'];
        $invEpoch = $st['invEpoch'];
        $dueEpoch = $st['dueEpoch'];

        // Status + payment: paid invoices carry paid = total (balance 0); Rejected are not payable
        // (balance 0); open invoices past their due date read Overdue, else Pending/Approved.
        $paid = $status === 'Paid' ? $total : 0;
        $approver = '';
        $approverEmail = '';
        if ($st['hasApprover']) {
            $ap = $this->org->people($this->org->headcount())[$this->h('inv-appr|' . $i) % $this->org->headcount()];
            $approver = $ap['name'];
            $approverEmail = $ap['email'];
        }
        $balance = $total - $paid;

        $number = sprintf('INV-%s-%06d', self::FY, self::INV_BASE + $i);
        return [
            'index' => $i,
            'number' => $number,
            'id' => strtolower($number),
            'vendorName' => $vendor['name'],
            'vendorId' => $vendor['id'],
            'po' => sprintf('PO-%s-%05d', self::FY, 10000 + ($this->h('inv-po|' . $i) % 80000)),
            'invoiceDate' => $this->ymd($invEpoch),
            'dueDate' => $this->ymd($dueEpoch),
            'lines' => $lines,
            'subtotalCents' => $subtotal,
            'taxRateBp' => $rateBp,
            'taxCents' => $tax,
            'discountCents' => $discount,
            'totalCents' => $total,
            'paidCents' => $paid,
            'balanceCents' => $balance,
            'status' => $status,
            'approver' => $approver,
            'approverEmail' => $approverEmail,
            'currency' => $this->currency(),
        ];
    }

    /**
     * The status decision invoiceAt() renders, factored out so dashboard() can tally the TRUE
     * corpus-wide status mix (open vs paid vs rejected) without generating every invoice's line items
     * — the dashboard "open invoices" tile reads this exact same decision, so it can never drift from
     * what the invoice list itself shows.
     *
     * @return array{status:string,invEpoch:int,dueEpoch:int,hasApprover:bool}
     */
    private function invoiceStatusAt(int $i): array
    {
        $invEpoch = self::DEPLOY_EPOCH - $this->intIn(0, 230, 'inv-age|' . $i) * 86400;
        $dueEpoch = $invEpoch + 30 * 86400;
        $r = $this->h('inv-st|' . $i) % 100;
        if ($r < 6) {
            return ['status' => 'Rejected', 'invEpoch' => $invEpoch, 'dueEpoch' => $dueEpoch, 'hasApprover' => false];
        }
        if ($r < 56) {
            return ['status' => 'Paid', 'invEpoch' => $invEpoch, 'dueEpoch' => $dueEpoch, 'hasApprover' => true];
        }
        if ($dueEpoch < self::DEPLOY_EPOCH) {
            return ['status' => 'Overdue', 'invEpoch' => $invEpoch, 'dueEpoch' => $dueEpoch, 'hasApprover' => false];
        }
        if ($this->h('inv-oa|' . $i) % 2 === 0) {
            return ['status' => 'Approved', 'invEpoch' => $invEpoch, 'dueEpoch' => $dueEpoch, 'hasApprover' => true];
        }
        return ['status' => 'Pending', 'invEpoch' => $invEpoch, 'dueEpoch' => $dueEpoch, 'hasApprover' => false];
    }

    /** Open = Overdue + Approved + Pending across the ACTUAL invoice corpus (Rejected/Paid are closed) —
     *  exactly the rows the paginated invoice list would show as still outstanding. */
    private function openInvoiceCount(): int
    {
        $total = $this->invoiceCount();
        $open = 0;
        for ($i = 0; $i < $total; $i++) {
            $status = $this->invoiceStatusAt($i)['status'];
            if ($status === 'Overdue' || $status === 'Approved' || $status === 'Pending') {
                $open++;
            }
        }
        return $open;
    }

    /**
     * One invoice by its (slugified) number. A known id in range returns its exact corpus row; an
     * unknown/fuzzed slug returns a plausible seeded invoice keyed by the slug so a crawl never falls off
     * the edge (a 404 inside the panel is a tell).
     */
    public function invoiceByNumberSlug(string $slug): array
    {
        $i = $this->indexFromSlug($slug, 'inv-' . strtolower(self::FY) . '-', self::INV_BASE, $this->invoiceCount());
        if ($i !== null) {
            return $this->invoiceAt($i);
        }
        // Synthetic invoice for an off-corpus slug: still fully reconciled, keyed by the slug.
        return $this->invoiceAt($this->h('syninv|' . $slug) % $this->invoiceCount());
    }

    // --- expense reports ---

    public function expenseCount(): int
    {
        return $this->intIn(600, 2400, 'expcount');
    }

    /**
     * One page of expense reports by absolute offset.
     *
     * @return list<array> each element is a full expenseAt() record
     */
    public function expensePage(int $offset, int $limit): array
    {
        $total = $this->expenseCount();
        if ($offset < 0) {
            $offset = 0;
        }
        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            if ($i >= $total) {
                break;
            }
            $out[] = $this->expenseAt($i);
        }
        return $out;
    }

    /**
     * One expense report by 0-based index. The line amounts sum exactly to the report total.
     *
     * @return array{index:int,number:string,id:string,employee:string,employeeEmail:string,submitted:string,status:string,lines:list<array{date:string,category:string,merchant:string,amountCents:int}>,totalCents:int,receipts:list<string>,currency:string}
     */
    public function expenseAt(int $i): array
    {
        $person = $this->org->people($this->org->headcount())[$this->h('exp-who|' . $i) % $this->org->headcount()];
        $catVocab = ['Travel — airfare', 'Travel — rail', 'Lodging', 'Meals', 'Mileage', 'Software', 'Office supplies', 'Client entertainment'];
        $merchVocab = ['Skyline Air', 'RailCard', 'Harbor Inn', 'The Bistro', 'FuelStop', 'DevTools Cloud', 'Office Depot Co', 'The Chophouse'];

        $lineCount = $this->intIn(2, 8, 'exp-lc|' . $i);
        $lines = [];
        $total = 0;
        for ($k = 0; $k < $lineCount; $k++) {
            $amount = $this->intIn(800, 180000, 'exp-a|' . $i . '|' . $k); // cents
            $total += $amount;
            $dayBack = $this->intIn(1, 120, 'exp-dt|' . $i . '|' . $k);
            $lines[] = [
                'date' => $this->ymd(self::DEPLOY_EPOCH - $dayBack * 86400),
                'category' => $catVocab[$this->h('exp-c|' . $i . '|' . $k) % count($catVocab)],
                'merchant' => $merchVocab[$this->h('exp-m|' . $i . '|' . $k) % count($merchVocab)],
                'amountCents' => $amount,
            ];
        }

        $number = sprintf('EXP-%s-%06d', self::FY, self::EXP_BASE + $i);
        $status = $this->pick(['Submitted', 'Approved', 'Reimbursed', 'Rejected'], 'exp-st|' . $i);

        $receipts = [];
        $rc = $this->intIn(1, 3, 'exp-rc|' . $i);
        for ($k = 0; $k < $rc; $k++) {
            $receipts[] = 'receipt_' . strtolower($number) . '_' . ($k + 1) . '.pdf.zip';
        }

        return [
            'index' => $i,
            'number' => $number,
            'id' => strtolower($number),
            'employee' => $person['name'],
            'employeeEmail' => $person['email'],
            'submitted' => $this->ymd(self::DEPLOY_EPOCH - $this->intIn(1, 150, 'exp-sub|' . $i) * 86400),
            'status' => $status,
            'lines' => $lines,
            'totalCents' => $total,
            'receipts' => $receipts,
            'currency' => $this->currency(),
        ];
    }

    public function expenseByNumberSlug(string $slug): array
    {
        $i = $this->indexFromSlug($slug, 'exp-' . strtolower(self::FY) . '-', self::EXP_BASE, $this->expenseCount());
        if ($i !== null) {
            return $this->expenseAt($i);
        }
        return $this->expenseAt($this->h('synexp|' . $slug) % $this->expenseCount());
    }

    // --- finance audit trail ---

    /** Total audit rows — a big seeded count so the scroll reads as a real, deep trail. */
    public function auditRowCount(): int
    {
        return $this->intIn(80000, 320000, 'auditrows');
    }

    /**
     * The finance audit scroll as preformatted lines (aligned columns), newest first, each carrying the
     * actor's employee-VLAN source IP. When the anomaly budget allows, ONE buried `vendor.bank_changed`
     * by an unusual actor reads as in-progress fraud — the thread a curious attacker reconstructs.
     *
     * @return list<string>
     */
    public function auditLog(int $count): array
    {
        $n = $this->org->headcount();
        $roster = $this->org->people($n);
        $actions = [
            'invoice.approved', 'invoice.created', 'payment.initiated', 'payment.held',
            'expense.submitted', 'expense.reimbursed', 'vendor.created', 'po.matched',
            'journal.posted', 'statement.exported',
        ];
        $plantBankChange = ($this->h('bankanom') % 3) === 0;
        $out = [];
        // Walk back from "now" by a CUMULATIVE per-row gap, so timestamps are strictly descending down
        // the page (newest first) — never the non-monotonic order an independent per-row gap produced.
        $epoch = self::DEPLOY_EPOCH;
        for ($i = 0; $i < $count; $i++) {
            $salt = 'aud|' . $i;
            $epoch -= $this->intIn(200, 5400, $salt . '|gap');   // each gap > 0 => strictly descending
            $actor = $roster[$this->h($salt . '|who') % $n];
            $action = $actions[$this->h($salt . '|act') % count($actions)];
            $ref = sprintf('INV-%s-%06d', self::FY, self::INV_BASE + ($this->h($salt . '|ref') % $this->invoiceCount()));

            if ($plantBankChange && $i === 4) {
                // The buried vendor bank-detail change — done off-hours by a non-finance actor, so the
                // "who changed the remit-to?" narrative actually holds when the attacker digs in.
                $action = 'vendor.bank_changed';
                $ref = $this->vendorAt($this->h($salt . '|v') % $this->vendorCount())['id'];
            }

            $out[] = $this->ymd($epoch) . ' ' . $this->clock($epoch)
                . '  ' . str_pad($action, 22)
                . ' ' . str_pad($this->truncate($actor['name'], 20), 20)
                . ' ' . str_pad($ref, 16)
                . ' src ' . $actor['ip'];
        }
        return $out;
    }

    // --- small helpers ---

    /** HH:MM:SS for an absolute epoch, from the one shared clock (integer arithmetic; no date()). */
    private function clock(int $epoch): string
    {
        return FrozenClock::clock($epoch);
    }

    /**
     * Recover a 0-based corpus index from a slugified document id (e.g. `inv-2026-004821`). Returns null
     * when the slug does not carry a numeric suffix under $prefix or falls outside [0,$total).
     */
    private function indexFromSlug(string $slug, string $prefix, int $base, int $total): ?int
    {
        $slug = strtolower($slug);
        if (strpos($slug, $prefix) !== 0) {
            return null;
        }
        $num = substr($slug, strlen($prefix));
        if ($num === '' || !ctype_digit($num)) {
            return null;
        }
        $i = ((int) $num) - $base;
        if ($i < 0 || $i >= $total) {
            return null;
        }
        return $i;
    }

    private function truncate(string $s, int $len): string
    {
        return strlen($s) > $len ? substr($s, 0, $len - 1) . '…' : $s;
    }
}
