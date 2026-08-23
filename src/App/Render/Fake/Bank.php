<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT corporate treasury for the deep office panel — company bank accounts, a
 * reconciling transaction ledger, and the corporate-card fleet. It is the greed lure's data spine
 * (spec §C.6): the fat "drainable" Reserve balance, the wire-out form, the masked card PANs.
 *
 * Design rules (deep-admin dashboard spec §C.6 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); ledger dates walk back from one frozen calendar day by integer
 *    civil-date arithmetic, so a static reload is byte-identical and never a tell.
 *  - ARITHMETIC CLOSES: dashboard cash on hand = Σ account balances; the ledger running balance is
 *    defined so each row's balance = the older row's balance + this row's signed amount (reconciles
 *    exactly down the page AND across pages); balances stay positive by construction.
 *  - SAFE: every banking coordinate is fabricated AND structurally invalid so nothing validates — the
 *    IBAN carries check digits "00" (never valid per ISO 13616), the routing number uses Federal
 *    Reserve prefix "00" (never assigned), the card PAN reveals with BIN "0000" and fails the Luhn
 *    check. Bank names are invented, not real institutions; no real BIN/BIC resolves. Account numbers
 *    are masked at rest to their last four.
 *  - COHERENT: card holders are the Org roster (one host = one company). Emails render at the persona
 *    domain the caller supplies.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/intdiv, no enums/promotion/str_contains/arrow-fns) so
 *    a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Bank
{
    /** Frozen calendar day the ledger's newest row reads; older rows walk back from here. Matches Cctv. */
    private const FROZEN_Y = 2026;
    private const FROZEN_M = 8;
    private const FROZEN_D = 23;

    /** A ledger's advertised depth is a big seeded constant; only the requested page is ever built. */
    private const LEDGER_MIN = 4200;
    private const LEDGER_MAX = 9800;

    /** Invented issuing banks — never a real institution (no real BIN/BIC resolves). */
    private const BANKS = [
        'Northbridge Trust', 'Fenwick Commercial Bank', 'Sterling Ridge Bank',
        'Camberwell Mutual', 'Ardent National', 'Halcyon Savings & Loan',
    ];

    /** The account roles the treasury draws from; Reserve is always present (the fat drainable one). */
    private const ACCOUNT_ROLES = [
        ['slug' => 'operating', 'name' => 'Operating', 'type' => 'Checking',     'min' => 250000,  'max' => 1600000],
        ['slug' => 'payroll',   'name' => 'Payroll',   'type' => 'Checking',     'min' => 90000,   'max' => 620000],
        ['slug' => 'tax',       'name' => 'Tax',       'type' => 'Savings',      'min' => 60000,   'max' => 420000],
        ['slug' => 'capital',   'name' => 'Capital Expenditure', 'type' => 'Savings', 'min' => 120000, 'max' => 940000],
    ];

    /** @var int */
    private $seed;

    /** @var string persona domain card-holder emails render at ('' -> Org's seeded fallback). */
    private $personaDomain;

    /** @var Org */
    private $org;

    /** @var array<int,array>|null cached account list */
    private $accountsCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->personaDomain = $personaDomain;
        $this->org = Org::fromSeed($seed, $personaDomain);
    }

    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|bank|' . $salt), 0, 15));
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

    /** A run of seeded decimal digits, e.g. for a masked account tail. */
    private function digits(int $n, string $salt): string
    {
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $out .= (string) ($this->h($salt . '|d|' . $i) % 10);
        }
        return $out;
    }

    // --- civil-date arithmetic (no date()/gmdate): days <-> Y-M-D, Hinnant's algorithm ---

    private function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= ($m <= 2) ? 1 : 0;
        $era = intdiv(($y >= 0 ? $y : $y - 399), 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    /** @return array{0:int,1:int,2:int} [year, month, day] */
    private function civilFromDays(int $z): array
    {
        $z += 719468;
        $era = intdiv(($z >= 0 ? $z : $z - 146096), 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp + ($mp < 10 ? 3 : -9);
        $y += ($m <= 2) ? 1 : 0;
        return [$y, $m, $d];
    }

    /** The frozen calendar day minus $back days, as YYYY-MM-DD (deterministic, never date()). */
    private function dateMinus(int $back): string
    {
        $c = $this->civilFromDays($this->daysFromCivil(self::FROZEN_Y, self::FROZEN_M, self::FROZEN_D) - $back);
        return sprintf('%04d-%02d-%02d', $c[0], $c[1], $c[2]);
    }

    // --- accounts ---

    /**
     * The company bank accounts (2-5), Reserve always first and holding the fat drainable balance.
     * All USD so dashboard cash on hand is a clean Σ of balances.
     *
     * @return list<array{id:string,slug:string,name:string,type:string,bank:string,currency:string,balance:int,accountMasked:string,accountLast4:string,routing:string,iban:string,bic:string,branch:string,status:string,opened:string}>
     */
    public function accounts(): array
    {
        if ($this->accountsCache !== null) {
            return $this->accountsCache;
        }
        $out = [];
        // Reserve: the money-market account carrying the headline balance (the wire-out lure).
        $out[] = $this->buildAccount('reserve', 'Reserve', 'Money Market', $this->intIn(1200000, 8400000, 'reserve|bal'));

        // Plus 1-3 more roles, deterministically chosen, so the estate is 2-4 accounts total.
        $extra = $this->intIn(1, 3, 'acctcount');
        $roles = self::ACCOUNT_ROLES;
        for ($i = 0; $i < $extra && $i < count($roles); $i++) {
            $r = $roles[$i];
            $out[] = $this->buildAccount($r['slug'], $r['name'], $r['type'], $this->intIn($r['min'], $r['max'], $r['slug'] . '|bal'));
        }
        $this->accountsCache = $out;
        return $out;
    }

    private function buildAccount(string $slug, string $name, string $type, int $balance): array
    {
        $last4 = $this->digits(4, $slug . '|acctno');
        // Routing: 9 digits with Federal Reserve prefix "00" (never assigned) -> structurally invalid.
        $routing = '00' . $this->digits(7, $slug . '|rt');
        // IBAN: country + check digits "00" (ISO 13616 forbids 00/01) + fabricated BBAN -> never valid.
        $iban = 'US00' . strtoupper($this->digits(4, $slug . '|ibk')) . $this->digits(12, $slug . '|iban');
        // BIC: unassigned bank code "ZZZZ", location "0X" -> resolves to no institution.
        $bic = 'ZZZZUS0' . chr(65 + ($this->h($slug . '|bic') % 26));

        return [
            'id' => 'acct-' . $slug,
            'slug' => $slug,
            'name' => $name,
            'type' => $type,
            'bank' => $this->pick(self::BANKS, $slug . '|bank'),
            'currency' => 'USD',
            'balance' => $balance,
            'accountMasked' => '••••••' . $last4,
            'accountLast4' => $last4,
            'routing' => $routing,
            'iban' => $iban,
            'bic' => $bic,
            'branch' => $this->intIn(100, 899, $slug . '|branch') . ' — ' . $this->pick(
                ['Downtown', 'Financial District', 'Midtown', 'Corporate Banking', 'Commercial Centre'],
                $slug . '|br'
            ),
            'status' => 'Active',
            'opened' => $this->dateMinus($this->intIn(730, 3200, $slug . '|opened')),
        ];
    }

    /**
     * One account by id. Returns a plausible account even for an unknown/fuzzed id (a 404 inside a
     * deep panel is a tell) — the slug seeds a deterministic detail keyed to itself.
     */
    public function account(string $id): array
    {
        foreach ($this->accounts() as $a) {
            if ($a['id'] === $id) {
                return $a;
            }
        }
        $slug = strpos($id, 'acct-') === 0 ? substr($id, 5) : $id;
        if ($slug === '') {
            $slug = 'operating';
        }
        return $this->buildAccount($slug, ucfirst(str_replace('-', ' ', $slug)), 'Checking', $this->intIn(40000, 900000, $slug . '|xbal'));
    }

    /**
     * Treasury summary — cash on hand is the exact Σ of account balances (arithmetic closes).
     *
     * @return array{cashOnHand:int,accounts:int,largest:int,largestName:string,cards:int,pendingWires:int,currency:string}
     */
    public function summary(): array
    {
        $accts = $this->accounts();
        $sum = 0;
        $largest = 0;
        $largestName = '';
        foreach ($accts as $a) {
            $sum += $a['balance'];
            if ($a['balance'] > $largest) {
                $largest = $a['balance'];
                $largestName = $a['name'];
            }
        }
        return [
            'cashOnHand' => $sum,
            'accounts' => count($accts),
            'largest' => $largest,
            'largestName' => $largestName,
            'cards' => $this->cardCount(),
            'pendingWires' => $this->intIn(0, 2, 'pendingwires'),
            'currency' => 'USD',
        ];
    }

    // --- transaction ledger (running balance reconciles by construction) ---

    /** Advertised ledger depth for an account (big seeded constant; only a page is ever built). */
    public function ledgerCount(string $accountId): int
    {
        return $this->intIn(self::LEDGER_MIN, self::LEDGER_MAX, $accountId . '|ledgercount');
    }

    /**
     * The balance the ledger shows AFTER the transaction at global index $g (0 = newest = today).
     * Anchored at the account's current balance and kept within a bounded band around it, so every
     * displayed balance is positive and near the live figure — and the per-row amount is derived FROM
     * these balances (below), which makes the running-balance column reconcile exactly.
     */
    private function balanceAt(array $acct, int $g): int
    {
        if ($g <= 0) {
            return $acct['balance'];
        }
        $band = intdiv($acct['balance'], 6);
        if ($band < 1) {
            $band = 1;
        }
        $wobble = ($this->h($acct['slug'] . '|bal|' . $g) % (2 * $band + 1)) - $band;
        return $acct['balance'] + $wobble;
    }

    /**
     * A page of ledger rows, newest first. amountSigned = balanceAt(g) - balanceAt(g+1), so
     * balanceAt(g) == balanceAt(g+1) + amountSigned by construction — the running balance reconciles
     * both down the page and across page boundaries. Dates walk monotonically back from the frozen day.
     *
     * @return list<array{date:string,ref:string,description:string,amountSigned:int,balance:int}>
     */
    public function ledgerPage(string $accountId, int $offset, int $limit): array
    {
        $acct = $this->account($accountId);
        if ($offset < 0) {
            $offset = 0;
        }
        if ($limit < 0) {
            $limit = 0;
        }
        $total = $this->ledgerCount($accountId);
        $out = [];
        for ($i = 0; $i < $limit; $i++) {
            $g = $offset + $i;
            if ($g >= $total) {
                break;
            }
            $balHere = $this->balanceAt($acct, $g);
            $balOlder = $this->balanceAt($acct, $g + 1);
            $amount = $balHere - $balOlder;
            $out[] = [
                'date' => $this->dateMinus($g),
                'ref' => $this->ledgerRef($acct['slug'], $g),
                'description' => $this->ledgerDesc($acct['slug'], $g, $amount),
                'amountSigned' => $amount,
                'balance' => $balHere,
            ];
        }
        return $out;
    }

    /** A source-document reference for a ledger row (display text; a fabricated, non-resolving id). */
    private function ledgerRef(string $slug, int $g): string
    {
        $kinds = ['INV', 'PO', 'WIRE', 'DEP', 'ACH', 'FEE'];
        $k = $kinds[$this->h($slug . '|refk|' . $g) % count($kinds)];
        return $k . '-2026-' . sprintf('%06d', $this->intIn(1, 899999, $slug . '|refn|' . $g));
    }

    private function ledgerDesc(string $slug, int $g, int $amount): string
    {
        $credits = ['Customer payment received', 'Inbound wire settlement', 'Interest posting', 'Cash deposit', 'Vendor refund'];
        $debits = ['Vendor payment (ACH)', 'Outbound wire', 'Card settlement', 'Payroll funding', 'Bank service fee', 'Tax remittance'];
        if ($amount >= 0) {
            return $credits[$this->h($slug . '|cd|' . $g) % count($credits)];
        }
        return $debits[$this->h($slug . '|dd|' . $g) % count($debits)];
    }

    /**
     * Statement export descriptors for an account (download rows). Every filename ends `.zip`/`.csv.zip`
     * — the only extensions the decoy-archive handler serves (spec E8).
     *
     * @return list<array{file:string,cells:list<string>}>
     */
    public function statements(string $accountId): array
    {
        $acct = $this->account($accountId);
        $out = [];
        $months = ['2026-08', '2026-07', '2026-06', '2025-12'];
        foreach ($months as $i => $mo) {
            $out[] = [
                'file' => 'statement_' . $acct['slug'] . '_' . $mo . '.csv.zip',
                'cells' => [$mo, 'CSV (zip)', number_format($this->intIn(180, 640, $acct['slug'] . '|stmt|' . $i)) . ' rows'],
            ];
        }
        return $out;
    }

    // --- corporate cards (masked; reveal is a per-card non-validating dummy, never a PAN) ---

    /** Fleet size — a small seeded corporate program, not tied to headcount. */
    public function cardCount(): int
    {
        return $this->intIn(6, 24, 'cardcount');
    }

    /**
     * The corporate-card fleet. last4 is fabricated; the PAN is only ever revealed via cardReveal()
     * and is structurally invalid. Holders are the Org roster (one company).
     *
     * @return list<array{id:string,holder:string,holderId:string,email:string,program:string,last4:string,masked:string,limit:int,spentMtd:int,expiry:string,status:string}>
     */
    public function cards(): array
    {
        $count = $this->cardCount();
        $people = $this->org->people($count);
        $programs = ['Purchasing', 'Travel & Expense', 'Executive'];
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = $this->buildCard($i, isset($people[$i]) ? $people[$i] : null);
        }
        return $out;
    }

    private function buildCard(int $i, ?array $person): array
    {
        $programs = ['Purchasing', 'Travel & Expense', 'Executive'];
        $last4 = $this->digits(4, 'card|last4|' . $i);
        $limit = $this->intIn(2, 50, 'card|limit|' . $i) * 1000;
        $spent = $this->h('card|spent|' . $i) % ($limit + 1);
        $holder = $person !== null ? $person['name'] : 'Cardholder ' . ($i + 1);
        $holderId = $person !== null ? $person['id'] : 'emp-' . (1001 + $i);
        $email = $person !== null ? $person['email'] : strtolower(str_replace(' ', '.', $holder)) . '@' . $this->org->domain();
        return [
            'id' => 'card-' . sprintf('%04d', 5100 + $i),
            'holder' => $holder,
            'holderId' => $holderId,
            'email' => $email,
            'program' => $programs[$this->h('card|prog|' . $i) % count($programs)],
            'last4' => $last4,
            'masked' => '•••• •••• •••• ' . $last4,
            'limit' => $limit,
            'spentMtd' => $spent,
            'expiry' => '••/••',
            'status' => ($this->h('card|st|' . $i) % 100) < 90 ? 'Active' : 'Suspended',
        ];
    }

    /** One card by id, with a plausible fallback for an unknown/fuzzed id. */
    public function card(string $id): array
    {
        foreach ($this->cards() as $c) {
            if ($c['id'] === $id) {
                return $c;
            }
        }
        $num = 0;
        if (strpos($id, 'card-') === 0 && ctype_digit(substr($id, 5))) {
            $num = ((int) substr($id, 5)) - 5100;
        }
        if ($num < 0) {
            $num = 0;
        }
        $people = $this->org->people($num + 1);
        return $this->buildCard($num, isset($people[$num]) ? $people[$num] : null);
    }

    /**
     * The "reveal" a card returns: a full-length PAN that is deterministically INVALID — BIN "0000"
     * (no issuer) and the 16 digits fail the Luhn check — so nothing downstream can validate or use it.
     * Never a real or checksum-valid card number.
     */
    public function cardReveal(string $id): string
    {
        $card = $this->card($id);
        $body = $this->digits(12, 'card|reveal|' . $id);
        $pan = '0000' . $body;                 // BIN 0000 = unassigned
        if ($this->luhnValid($pan)) {
            // Flip the last digit so the number can never pass a Luhn check.
            $last = (int) substr($pan, -1);
            $pan = substr($pan, 0, 15) . (string) (($last + 1) % 10);
        }
        return trim(chunk_split($pan, 4, ' '));
    }

    private function luhnValid(string $num): bool
    {
        $sum = 0;
        $alt = false;
        for ($i = strlen($num) - 1; $i >= 0; $i--) {
            $d = (int) $num[$i];
            if ($alt) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $sum += $d;
            $alt = !$alt;
        }
        return $sum % 10 === 0;
    }

    /**
     * The deterministic, inert reference a wire request is assigned. Stable per (account, beneficiary,
     * amount) slot, varies per deploy. No funds move; the honeypot never touches a real system.
     */
    public function wireRef(string $accountId, string $slot): string
    {
        return 'WIRE-2026-' . strtoupper(substr(hash('sha256', $this->seed . '|wire|' . $accountId . '|' . $slot), 0, 6));
    }
}
