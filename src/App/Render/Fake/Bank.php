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
 *  - SAFE: every banking coordinate is fabricated and can never touch a real account. The IBAN carries
 *    check digits "00" (never valid per ISO 13616) and the routing number uses Federal Reserve prefix
 *    "00" (never assigned). Corporate-card PANs are the ONE deliberate exception: they are Luhn-VALID —
 *    built on published test-card BIN ranges (network sandbox space, never issued to a real cardholder)
 *    plus a computed Luhn check digit — with valid-FORMAT expiry + CVV, so a scanner's card detector
 *    treats them as live numbers worth trying (that engagement is the point), yet the number can never
 *    be a real card. Bank names are invented, not real institutions; no real BIN/BIC resolves. Account
 *    numbers are masked at rest to their last four; full PANs appear only on the explicit card reveal.
 *  - COHERENT: card holders are the Org roster (one host = one company). Emails render at the persona
 *    domain the caller supplies. The Payroll account balance is sized off `Payroll::currentNet()` for
 *    the same seed (not a generic seeded range), so it can always cover at least one real run.
 *  - COLD WALLETS vs everything else: the 4 real ETH_RESERVE addresses are the only crypto addresses
 *    this class returns that the section ever shows in full (an attacker verifies them on-chain and
 *    sees real money — the hook). Every other crypto address this class hands back — staking
 *    validators, tx-history counterparties — is fabricated (fakeEvmAddress()) and the section masks
 *    it before it ever reaches output; the strategy only works if a fake address is never shown full.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/intdiv, no enums/promotion/str_contains/arrow-fns) so
 *    a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Bank
{
    use SeededInstanceCache;

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

    /** Fictional external counterparties a wire attempt names as beneficiary — never a real company. */
    private const WIRE_BENEFICIARIES = [
        'Meridian Supply Co', 'Northfield Logistics Ltd', 'Arcadia Partners LLC', 'Bluecrest Holdings',
        'Halden & Vance Trading', 'Overseas Commerce Ltd', 'Instrument Freight Group', 'Palisade Sourcing Inc',
    ];

    /** Why a "completed" wire reads as reversed on the ledger — never a real compliance body/policy name. */
    private const REVERSAL_REASONS = [
        'Compliance hold — sanctions screening re-review',
        'Dual-authorization mismatch — second approver revoked',
        'Beneficiary bank rejected — instructions under review',
        'Compliance hold — pending secondary review',
    ];

    /** Approver job titles for the wire-authorization roster (Treasury/Finance leadership, never real people). */
    private const APPROVER_ROLES = ['CFO', 'Treasury Director', 'Controller', 'VP Finance', 'Treasury Analyst'];

    /**
     * HOUSEKEEPING — do not remove this note: these 4 addresses are REAL, currently-funded Ethereum
     * addresses (independently verified live via `eth_getBalance` against a public RPC, 2026-08-24 —
     * exact method + re-check commands in `funnypot-project/scratchpad/crypto-addresses.md`, tracked
     * in `funnypot/ROADMAP.md`). They exist ONLY as a deliberately-inert "greed lure": this project
     * never holds or derives their private keys — the wallet.json keystore decoy built by
     * `scripts/build-decoys.sh` carries NONSENSE ciphertext/mac, so funds can never move through the
     * honeypot. `ethBalance` is a point-in-time snapshot and WILL drift as the real chain moves; a
     * periodic job should re-verify each address and swap out any that empties (same source file has
     * the re-check method).
     */
    private const ETH_RESERVE = [
        ['id' => 'eth-a', 'label' => 'Cold Reserve A', 'address' => '0x638A2f4c652DcdD671Adc9b712e0DaBF01E256C5', 'ethBalance' => 500.19185120],
        ['id' => 'eth-b', 'label' => 'Cold Reserve B', 'address' => '0x68C936f2A0EdEd3c28293af9BEdD2E01D4A4c95C', 'ethBalance' => 500.09904015],
        ['id' => 'eth-c', 'label' => 'Cold Reserve C', 'address' => '0xFc8bD5408d04Cd82465F929d37d8279f464e8D8F', 'ethBalance' => 500.02748191],
        ['id' => 'eth-d', 'label' => 'Cold Reserve D', 'address' => '0x27684c1938239e09bC74c607ceCa0C718dedcaC6', 'ethBalance' => 500.00692444],
    ];

    /** Fixed display price (USD/ETH) — a point-in-time snapshot baked in at authoring time, never a
     *  live feed fetched at request time (no external call on the request path). */
    private const ETH_USD_PRICE = 2457.77;

    /** @var int */
    private $seed;

    /** @var string persona domain card-holder emails render at ('' -> Org's seeded fallback). */
    private $personaDomain;

    /** @var Org */
    private $org;

    /** @var Payroll the seed's real payroll, so the Payroll account balance can be sized to cover it. */
    private $payroll;

    /** @var array<int,array>|null cached account list */
    private $accountsCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->personaDomain = $personaDomain;
        $this->org = Org::fromSeed($seed, $personaDomain);
        $this->payroll = Payroll::fromSeed($seed, $personaDomain);
    }

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

    /**
     * A deterministic, valid-FORMAT (never real) EVM address: "0x" + 40 hex digits. Every crypto
     * address that is NOT one of the 4 real cold-wallet addresses (self::ETH_RESERVE) is built this
     * way — staking validators, tx-history counterparties, anything else — and the section masks it
     * at render (a fabricated value shown in full would be a verifiable on-chain mismatch; see
     * ETH_RESERVE's docblock and BankSection::maskEvmAddress()).
     */
    private function fakeEvmAddress(string $salt): string
    {
        return '0x' . substr(hash('sha256', $this->seed . '|evmaddr|' . $salt), 0, 40);
    }

    /**
     * A masked fake phone in the reserved fictional range 555-0100..555-0199 (NANP N11/555 fictional
     * block) — structurally never a real subscriber number, regardless of area code context. `full`
     * exists for completeness/testing; the panel only ever renders `masked` (five dots + last three).
     *
     * @return array{full:string,last3:string,masked:string}
     */
    private function fakePhone(string $salt): array
    {
        $n = $this->intIn(0, 99, $salt . '|phn');
        $block = '01' . sprintf('%02d', $n);   // always 0100-0199
        $last3 = substr($block, -3);
        return ['full' => '555-' . $block, 'last3' => $last3, 'masked' => '•••••' . $last3];
    }

    // --- civil-date arithmetic (the one shared frozen "now"; no date()/gmdate) ---

    /** The frozen calendar day minus $back days, as YYYY-MM-DD (deterministic, never date()). */
    private function dateMinus(int $back): string
    {
        return FrozenClock::ymdFromDays(FrozenClock::nowDays() - $back);
    }

    // --- accounts ---

    /**
     * The company bank accounts (2-5), Reserve always first and holding the fat drainable balance.
     * All USD so dashboard cash on hand is a clean Σ of balances.
     *
     * @return list<array{id:string,slug:string,name:string,type:string,bank:string,currency:string,balance:int,accountMasked:string,accountLast4:string,routing:string,iban:string,bic:string,branch:string,status:string,openedDaysAgo:int,opened:string}>
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
            // Payroll is sized off the seed's actual monthly net (never the generic role range) so it
            // can always cover at least one real run; every other role keeps its generic seeded band.
            $balanceDollars = $r['slug'] === 'payroll'
                ? $this->payrollAccountBalance()
                : $this->intIn($r['min'], $r['max'], $r['slug'] . '|bal');
            $out[] = $this->buildAccount($r['slug'], $r['name'], $r['type'], $balanceDollars);
        }
        $this->accountsCache = $out;
        return $out;
    }

    /** The Payroll account balance, sized ~1-2x the seed's actual monthly net payroll (Payroll's own
     *  single source of truth) so the funding account can always cover at least one real run, instead
     *  of a generic range unrelated to what this company actually pays out each month. */
    private function payrollAccountBalance(): int
    {
        $net = $this->payroll->currentNet();
        $multiplierPct = 100 + ($this->h('payroll|multiplier') % 101);   // 1.00x-2.00x
        $balance = intdiv($net * $multiplierPct, 100);
        return $balance < 1 ? 1 : $balance;
    }

    /** @param int $balanceDollars whole-dollar balance; stored (and returned) as integer cents. */
    private function buildAccount(string $slug, string $name, string $type, int $balanceDollars): array
    {
        $last4 = $this->digits(4, $slug . '|acctno');
        // Routing: 9 digits with Federal Reserve prefix "00" (never assigned) -> structurally invalid.
        $routing = '00' . $this->digits(7, $slug . '|rt');
        // IBAN: country + check digits "00" (ISO 13616 forbids 00/01) + fabricated BBAN -> never valid.
        $iban = 'US00' . strtoupper($this->digits(4, $slug . '|ibk')) . $this->digits(12, $slug . '|iban');
        // BIC: unassigned bank code "ZZZZ", location "0X" -> resolves to no institution.
        $bic = 'ZZZZUS0' . chr(65 + ($this->h($slug . '|bic') % 26));

        // How long the account has been open, in days — the ledger clamps its depth to this so the
        // visible transaction history can never predate the account's own open date.
        $openedDaysAgo = $this->intIn(730, 3200, $slug . '|opened');

        return [
            'id' => 'acct-' . $slug,
            'slug' => $slug,
            'name' => $name,
            'type' => $type,
            'bank' => $this->pick(self::BANKS, $slug . '|bank'),
            'currency' => 'USD',
            'balance' => $balanceDollars * 100,          // integer cents (finance-family convention)
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
            'openedDaysAgo' => $openedDaysAgo,
            'opened' => $this->dateMinus($openedDaysAgo),
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

    /** Transactions posted per calendar day for an account (a few, never exactly one — real ledgers cluster). */
    private function txPerDay(string $slug): int
    {
        return $this->intIn(1, 4, $slug . '|txperday');
    }

    /**
     * Advertised ledger depth for an account. A big seeded constant, but CLAMPED so the oldest row can
     * never predate the account's open date: with a few transactions packed per day, the deepest the
     * history can reach back is (days-open x tx/day) rows. Only the requested page is ever built.
     */
    public function ledgerCount(string $accountId): int
    {
        $acct = $this->account($accountId);
        $band = $this->intIn(self::LEDGER_MIN, self::LEDGER_MAX, $accountId . '|ledgercount');
        $capacity = $acct['openedDaysAgo'] * $this->txPerDay($acct['slug']);
        if ($capacity < 1) {
            $capacity = 1;
        }
        return $band < $capacity ? $band : $capacity;
    }

    /**
     * The balance the ledger shows AFTER the transaction at global index $g (0 = newest = today).
     * Anchored at the account's current balance and kept within a bounded band around it, so every
     * displayed balance is positive and near the live figure. The wobble carries the row parity in its
     * low bit, so two adjacent rows can never share a balance — which makes the per-row amount (derived
     * as the difference of neighbouring balances) always non-zero, i.e. never a $0 ledger row.
     */
    private function balanceAt(array $acct, int $g): int
    {
        if ($g <= 0) {
            return $acct['balance'];
        }
        $band = intdiv($acct['balance'], 12);
        if ($band < 1) {
            $band = 1;
        }
        $mag = $this->h($acct['slug'] . '|bal|' . $g) % $band;            // [0, band-1]
        $signed = ($this->h($acct['slug'] . '|sgn|' . $g) % 2) === 1 ? $mag : -$mag;
        $wobble = $signed * 2 + ($g % 2);                                  // parity in the low bit
        return $acct['balance'] + $wobble;
    }

    /**
     * A page of ledger rows, newest first. amountSigned = balanceAt(g) - balanceAt(g+1), so
     * balanceAt(g) == balanceAt(g+1) + amountSigned by construction — the running balance reconciles
     * both down the page and across page boundaries, and is never $0. Dates walk monotonically back from
     * the frozen day, several rows per day, so the oldest row never predates the account open date.
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
        $perDay = $this->txPerDay($acct['slug']);
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
                'date' => $this->dateMinus(intdiv($g, $perDay)),
                'ref' => $this->ledgerRef($acct['slug'], $g),
                'description' => $this->ledgerDesc($acct['slug'], $g, $amount),
                'amountSigned' => $amount,
                'balance' => $balHere,
            ];
        }
        return $out;
    }

    /**
     * A bank-native payment-instrument reference for a ledger row (display text; fabricated, non-resolving).
     * Deliberately NOT an INV-/PO- reference: a bank ledger cites the payment instrument, not a supplier
     * invoice number, so these can never collide with (and contradict) the Finance/Vendors invoice+PO spaces.
     */
    private function ledgerRef(string $slug, int $g): string
    {
        $kinds = ['WIRE', 'ACH', 'DEP', 'CHK', 'POS', 'FEE', 'TFR'];
        $k = $kinds[$this->h($slug . '|refk|' . $g) % count($kinds)];
        return $k . '-' . FrozenClock::year() . '-' . sprintf('%06d', $this->intIn(1, 899999, $slug . '|refn|' . $g));
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
        // A Luhn-VALID PAN on a published test-card BIN (network sandbox space, never issued to a real
        // cardholder). Passes a card validator so an attacker treats it as a live number to try, yet can
        // never be a real card. The check digit is computed; last4 derives from the full PAN.
        $net = self::TEST_BINS[$this->h('card|net|' . $i) % count(self::TEST_BINS)];
        $body = $net['bin'] . $this->digits($net['len'] - strlen($net['bin']) - 1, 'card|acct|' . $i);
        $pan = $body . $this->luhnCheckDigit($body);
        $last4 = substr($pan, -4);
        $limit = $this->intIn(2, 50, 'card|limit|' . $i) * 1000 * 100;   // integer cents
        $spent = $this->h('card|spent|' . $i) % ($limit + 1);
        $holder = $person !== null ? $person['name'] : 'Cardholder ' . ($i + 1);
        $holderId = $person !== null ? $person['id'] : 'emp-' . (1001 + $i);
        $email = $person !== null ? $person['email'] : strtolower(str_replace(' ', '.', $holder)) . '@' . $this->org->domain();
        // Valid-format expiry in the future relative to the panel's frozen 2026 "now", + a network CVV.
        $expiry = sprintf('%02d/%02d', 1 + ($this->h('card|expm|' . $i) % 12), 27 + ($this->h('card|expy|' . $i) % 4));
        return [
            'id' => 'card-' . sprintf('%04d', 5100 + $i),
            'holder' => $holder,
            'holderId' => $holderId,
            'email' => $email,
            'program' => $programs[$this->h('card|prog|' . $i) % count($programs)],
            'network' => $net['name'],
            'pan' => $pan,
            'last4' => $last4,
            'masked' => $this->maskPan($net['len'], $last4),
            'expiry' => $expiry,
            'cvv' => $this->digits($net['cvv'], 'card|cvv|' . $i),
            'limit' => $limit,
            'spentMtd' => $spent,
            'status' => ($this->h('card|st|' . $i) % 100) < 90 ? 'Active' : 'Suspended',
        ];
    }

    /**
     * Published test-card BIN ranges (network sandbox space — never issued to a real cardholder). A PAN
     * built on one of these + a computed Luhn check digit passes a card validator but can never be real.
     * Deliberately NOT the headline 424242/555555/378282 numbers every tutorial quotes — a
     * payments-literate attacker recognizes those on sight. These are other genuinely-published
     * processor sandbox BINs (Stripe's alternate test ranges), same guarantee, just less iconic.
     */
    private const TEST_BINS = [
        ['name' => 'Visa',       'bin' => '400002', 'len' => 16, 'cvv' => 3],
        ['name' => 'Visa',       'bin' => '401288', 'len' => 16, 'cvv' => 3],
        ['name' => 'Mastercard', 'bin' => '510510', 'len' => 16, 'cvv' => 3],
        ['name' => 'Mastercard', 'bin' => '520082', 'len' => 16, 'cvv' => 3],
        ['name' => 'Amex',       'bin' => '371449', 'len' => 15, 'cvv' => 4],
    ];

    /** Mask all but the last four, in the network's grouping (Amex 4-6-5, others 4-4-4-4). */
    private function maskPan(int $len, string $last4): string
    {
        return $len === 15 ? '•••• •••••• •' . $last4 : '•••• •••• •••• ' . $last4;
    }

    /** The Luhn check digit that makes ($partial . digit) pass the Luhn test. */
    private function luhnCheckDigit(string $partial): string
    {
        $sum = 0;
        $alt = true;   // appended check digit is rightmost (not doubled), so $partial's last digit IS doubled
        for ($i = strlen($partial) - 1; $i >= 0; $i--) {
            $d = (int) $partial[$i];
            if ($alt) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $sum += $d;
            $alt = !$alt;
        }

        return (string) ((10 - ($sum % 10)) % 10);
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
     * The "reveal" a card returns: the card's full Luhn-VALID PAN, grouped for display. Built on a
     * published test-card BIN (network sandbox space, never issued to a real cardholder), so it passes a
     * card validator — an attacker who copies it out will try to use it — yet can never be a real card.
     * Ends in the same last four the masked views show.
     */
    public function cardReveal(string $id): string
    {
        return trim(chunk_split($this->card($id)['pan'], 4, ' '));
    }

    /**
     * The deterministic, inert reference a wire request is assigned. Stable per (account, beneficiary,
     * amount) slot, varies per deploy. No funds move; the honeypot never touches a real system.
     */
    public function wireRef(string $accountId, string $slot): string
    {
        return 'WIRE-' . FrozenClock::year() . '-' . strtoupper(substr(hash('sha256', $this->seed . '|wire|' . $accountId . '|' . $slot), 0, 6));
    }

    /** The masked phone a wire/crypto-send 2FA step claims to have texted a code to. Never validated —
     *  any code advances the gauntlet; this only supplies the display text. */
    public function wireInitiatorPhone(string $slot): array
    {
        return $this->fakePhone('initiator|' . $slot);
    }

    /** A deterministic display amount for the CURRENT wire attempt (the confirm step's "sent" figure).
     *  Bounded well under the account balance so it always reads as plausible. */
    public function wireAttemptAmount(string $accountId): int
    {
        $acct = $this->account($accountId);
        $ceiling = intdiv($acct['balance'], 100);
        $ceiling = $ceiling < 5000 ? 5000 : $ceiling;
        $cap = $ceiling < 400000 ? $ceiling : 400000;
        return $this->intIn(5000, $cap, $accountId . '|wireattemptamt') * 100;
    }

    /**
     * Recent outbound wire ATTEMPTS for an account's ledger/pending view — every one already shows as
     * reversed/clawed back (the complete-then-reversal gauntlet: a submitted wire always "succeeds"
     * then always reads as bounced here). DISPLAY-ONLY rows, distinct from the reconciling
     * ledgerPage() entries, so the running-balance arithmetic invariant is untouched; always present,
     * always reversed — the money never actually left, and the page never claims otherwise.
     *
     * @return list<array{date:string,ref:string,beneficiary:string,amount:int,status:string,reason:string}>
     */
    public function recentWireAttempts(string $accountId): array
    {
        $acct = $this->account($accountId);
        $slug = $acct['slug'];
        $ceiling = intdiv($acct['balance'], 100);
        $ceiling = $ceiling < 6000 ? 6000 : $ceiling;
        $cap = $ceiling < 250000 ? $ceiling : 250000;
        $count = $this->intIn(2, 4, $slug . '|wireattemptcount');
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $amount = $this->intIn(5000, $cap, $slug . '|wireattemptamt|' . $i) * 100;
            $out[] = [
                'date' => $this->dateMinus($this->intIn(0, 6, $slug . '|wireattemptdate|' . $i)),
                'ref' => $this->wireRef($accountId, 'attempt|' . $i),
                'beneficiary' => $this->pick(self::WIRE_BENEFICIARIES, $slug . '|wireattemptben|' . $i),
                'amount' => $amount,
                'status' => 'Reversed — compliance hold',
                'reason' => $this->pick(self::REVERSAL_REASONS, $slug . '|wireattemptreason|' . $i),
            ];
        }
        return $out;
    }

    // --- approvers (dual-authorization roster; the 2FA-bypass illusion) ---

    /**
     * The wire-authorization roster, drawn from the ONE company org so a name never contradicts the
     * employee directory. Every phone is fake (555-01xx); "2FA" is a display-only status, never real.
     *
     * @return list<array{id:string,personId:string,name:string,role:string,email:string,phoneFull:string,phoneLast3:string,phoneMasked:string,twoFa:string}>
     */
    public function approvers(): array
    {
        $count = $this->intIn(3, 6, 'approvercount');
        $people = $this->org->people($count);
        $out = [];
        foreach ($people as $i => $p) {
            $phone = $this->fakePhone('approver|' . $i);
            $out[] = [
                'id' => 'appr-' . (1 + $i),
                'personId' => $p['id'],
                'name' => $p['name'],
                'role' => self::APPROVER_ROLES[$this->h('approverrole|' . $i) % count(self::APPROVER_ROLES)],
                'email' => $p['email'],
                'phoneFull' => $phone['full'],
                'phoneLast3' => $phone['last3'],
                'phoneMasked' => $phone['masked'],
                'twoFa' => 'Enabled',
            ];
        }
        return $out;
    }

    /** One approver by id, with a plausible fallback for an unknown/fuzzed id (never a dead end). */
    public function approver(string $id): array
    {
        $list = $this->approvers();
        foreach ($list as $a) {
            if ($a['id'] === $id) {
                return $a;
            }
        }
        return $list[$this->h('approverfallback|' . $id) % count($list)];
    }

    /** The "new" masked phone an approver's reset-2FA flow claims to text a verification code to. */
    public function approverNewPhone(string $apprId): array
    {
        return $this->fakePhone('approverreset|' . $apprId);
    }

    /** A DIFFERENT approver than $exceptApproverId — guaranteed distinct (the roster always has >= 3).
     *  Used so a "phone updated" win still leaves the wire hold needing a signer the attacker hasn't
     *  touched: the illusion of 2FA-bypass never actually reduces the dual-authorization requirement. */
    public function otherApprover(string $exceptApproverId): array
    {
        $list = $this->approvers();
        $idx = $this->h('otherapprover|' . $exceptApproverId) % count($list);
        if ($list[$idx]['id'] === $exceptApproverId) {
            $idx = ($idx + 1) % count($list);
        }
        return $list[$idx];
    }

    /** The approver a given wire/account cites as its outstanding second signature — deterministic
     *  per slot, independent of anything an attacker just "fixed" on the approvers screen. */
    public function assignedApprover(string $slot): array
    {
        $list = $this->approvers();
        return $list[$this->h('assignedapprover|' . $slot) % count($list)];
    }

    // --- pending wires awaiting approval (more green; every approve is still a soft-deny) ---

    /**
     * A queue of large outbound wires "awaiting approval" across the treasury — always present, never
     * approvable. `requestedBy` is a roster employee (not necessarily an approver, so the "OTHER
     * approver" who must sign off always reads as a distinct dual-authorization gate).
     *
     * @return list<array{id:string,accountId:string,accountName:string,beneficiary:string,amount:int,currency:string,requestedDate:string,requestedBy:string}>
     */
    public function pendingApprovals(): array
    {
        $accts = $this->accounts();
        $headcount = $this->org->headcount();
        $count = $this->intIn(3, 6, 'pendingapprovalscount');
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = $this->buildPendingApproval('pnd-' . sprintf('%04d', 100 + $i), $accts, $headcount, 'pendapp|' . $i);
        }
        return $out;
    }

    /** One pending-approval row by id, with a plausible fallback for an unknown/fuzzed id. */
    public function pendingApproval(string $id): array
    {
        foreach ($this->pendingApprovals() as $p) {
            if ($p['id'] === $id) {
                return $p;
            }
        }
        return $this->buildPendingApproval($id, $this->accounts(), $this->org->headcount(), 'pendappfallback|' . $id);
    }

    /** @param list<array> $accts */
    private function buildPendingApproval(string $id, array $accts, int $headcount, string $salt): array
    {
        $acct = $accts[$this->h($salt . '|acct') % count($accts)];
        $ceiling = intdiv($acct['balance'], 100);
        $ceiling = $ceiling < 20000 ? 20000 : $ceiling;
        $cap = $ceiling < 900000 ? $ceiling : 900000;
        $amount = $this->intIn(20000, $cap, $salt . '|amt') * 100;
        $empIdx = $this->h($salt . '|by') % $headcount;
        $requester = $this->org->person('emp-' . (1001 + $empIdx));
        return [
            'id' => $id,
            'accountId' => $acct['id'],
            'accountName' => $acct['name'],
            'beneficiary' => $this->pick(self::WIRE_BENEFICIARIES, $salt . '|ben'),
            'amount' => $amount,
            'currency' => $acct['currency'],
            'requestedDate' => $this->dateMinus($this->intIn(0, 5, $salt . '|date')),
            'requestedBy' => $requester !== null ? $requester['name'] : 'Treasury Ops',
        ];
    }

    // --- ETH digital asset reserve (crypto treasury; real addresses, garbage keys — see ETH_RESERVE) ---

    /**
     * The ETH cold-storage tranches — real, verifiable addresses and their real balances, framed as
     * deliberate reserve tranching. Displayed fiat uses the fixed ETH_USD_PRICE snapshot (no live
     * price call at request time).
     *
     * @return list<array{id:string,label:string,chain:string,address:string,ethBalance:float,usdCents:int}>
     */
    public function crypto(): array
    {
        $out = [];
        foreach (self::ETH_RESERVE as $t) {
            $out[] = [
                'id' => $t['id'],
                'label' => $t['label'],
                'chain' => 'Ethereum',
                'address' => $t['address'],
                'ethBalance' => $t['ethBalance'],
                'usdCents' => (int) round($t['ethBalance'] * self::ETH_USD_PRICE * 100),
            ];
        }
        return $out;
    }

    /** @return array{totalEth:float,totalUsdCents:int,tranches:int} */
    public function cryptoSummary(): array
    {
        $rows = $this->crypto();
        $totalEth = 0.0;
        $totalUsdCents = 0;
        foreach ($rows as $r) {
            $totalEth += $r['ethBalance'];
            $totalUsdCents += $r['usdCents'];
        }
        return ['totalEth' => $totalEth, 'totalUsdCents' => $totalUsdCents, 'tranches' => count($rows)];
    }

    /** One reserve tranche by id, with a plausible fallback for an unknown/fuzzed id (always one of
     *  the 4 real tranches — never a 5th invented address, so every id resolves to a verifiable one). */
    public function cryptoAddress(string $id): array
    {
        $rows = $this->crypto();
        foreach ($rows as $r) {
            if ($r['id'] === $id) {
                return $r;
            }
        }
        return $rows[$this->h('cryptofallback|' . $id) % count($rows)];
    }

    /** Advertised on-chain tx depth for a tranche — a seeded constant; only the requested page is built. */
    public function cryptoTxCount(string $addrId): int
    {
        $addr = $this->cryptoAddress($addrId);
        return $this->intIn(40, 140, $addr['id'] . '|txcount');
    }

    /**
     * A page of seeded, plausible-looking ETH transaction history for a tranche — flavor/bait only; it
     * does not need to reconcile to the (real, externally fixed) balance the way the bank ledger does.
     * `hash`/`counterparty` are fabricated 0x values; `counterparty` is never one of our own 4 addresses.
     *
     * @return list<array{date:string,hash:string,direction:string,counterparty:string,amountEth:float,status:string}>
     */
    public function cryptoTxHistory(string $addrId, int $offset, int $limit): array
    {
        $addr = $this->cryptoAddress($addrId);
        $total = $this->cryptoTxCount($addrId);
        $out = [];
        for ($i = 0; $i < $limit; $i++) {
            $g = $offset + $i;
            if ($g >= $total) {
                break;
            }
            $out[] = [
                'date' => $this->dateMinus(intdiv($g, 2)),
                'hash' => '0x' . hash('sha256', $this->seed . '|ethtx|' . $addr['id'] . '|' . $g),
                'direction' => ($this->h($addr['id'] . '|txdir|' . $g) % 2) === 0 ? 'in' : 'out',
                'counterparty' => '0x' . substr(hash('sha256', $this->seed . '|ethcp|' . $addr['id'] . '|' . $g), 0, 40),
                'amountEth' => $this->intIn(10, 400000, $addr['id'] . '|txamt|' . $g) / 10000.0,
                'status' => 'Confirmed',
            ];
        }
        return $out;
    }

    /** The fake broadcast tx hash a crypto "Send" flow gets stuck showing — deterministic, never a
     *  real transaction; nothing is ever actually relayed to any network. */
    public function cryptoSendTxHash(string $addrId, string $slot): string
    {
        return '0x' . hash('sha256', $this->seed . '|ethsend|' . $addrId . '|' . $slot);
    }

    // --- ETH staking decoy (crypto-mask-staking spec §3) ---
    //
    // A large fabricated staking position layered onto the (real) reserve narrative: "we also stake
    // some of the treasury." Every validator/withdrawal address here is FAKE — a real cold wallet
    // staking our amount would be a mismatch a chain lookup could disprove — so BankSection masks
    // every one of them, same as it masks tx-history counterparties. Fully deterministic and
    // time()-free like the rest of this class; the ONE exception (reward ages tracking real "now")
    // lives entirely in BankSection, not here — see its stakingRewardAge() docblock.

    /** A plausible ETH staking APR band (basis points x10, i.e. 320 = 3.20%). */
    private const STAKING_APR_BP = [320, 410, 480];

    private const STAKING_REWARD_TYPES = ['Attestation reward', 'Proposer reward', 'Sync committee reward'];

    /** Reasons an unstake request reads as failed — never a real compliance policy/body name. */
    private const STAKING_UNSTAKE_FAILURE_REASONS = [
        'Validator exit rejected — signature mismatch',
        'Slashing-risk hold — pending review',
        'Withdrawal credentials mismatch',
    ];

    /**
     * The fake validators the "staked" ETH is spread across. Amounts sit near the real 32 ETH
     * deposit size plus a seeded amount of accrued (unwithdrawn) reward, so a scanner sees numbers
     * shaped like genuine validators, not round bait figures.
     *
     * @return list<array{id:string,address:string,stakedEth:float,status:string}>
     */
    public function stakingValidators(): array
    {
        $count = $this->intIn(40, 96, 'staking|validatorcount');
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = [
                'id' => 'val-' . sprintf('%04d', 7000 + $i),
                'address' => $this->fakeEvmAddress('validator|' . $i),
                'stakedEth' => 32.0 + ($this->intIn(0, 3500, 'staking|amt|' . $i) / 1000.0),
                'status' => 'Active',
            ];
        }
        return $out;
    }

    /**
     * Staking overview totals — totalStakedEth is the exact Σ of the validator amounts (arithmetic
     * closes, same rule the account balances follow).
     *
     * @return array{totalStakedEth:float,validatorCount:int,apr:float,usdCents:int,status:string}
     */
    public function stakingSummary(): array
    {
        $validators = $this->stakingValidators();
        $total = 0.0;
        foreach ($validators as $v) {
            $total += $v['stakedEth'];
        }
        $aprBp = self::STAKING_APR_BP[$this->h('staking|apr') % count(self::STAKING_APR_BP)];
        return [
            'totalStakedEth' => $total,
            'validatorCount' => count($validators),
            'apr' => $aprBp / 100.0,
            'usdCents' => (int) round($total * self::ETH_USD_PRICE * 100),
            'status' => 'Active',
        ];
    }

    /**
     * Seeded staking-reward rows: validator, type, amount, and a fixed seeded `ageOffsetSeconds` the
     * SECTION turns into a live "Nh ago" string at render (see BankSection::stakingRewardAge()). This
     * method itself is 100% deterministic — no time()/date() — the offset is just a display input,
     * not a clock reading. Ordered oldest-offset-first-is-last (ascending offset = newest first), and
     * that order never reshuffles between requests since it does not depend on any live clock.
     *
     * @return list<array{validatorId:string,validatorAddress:string,type:string,amountEth:float,ageOffsetSeconds:int}>
     */
    public function stakingRewards(): array
    {
        $validators = $this->stakingValidators();
        $count = $this->intIn(10, 18, 'staking|rewardcount');
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $v = $validators[$this->h('staking|rewardval|' . $i) % count($validators)];
            $out[] = [
                'validatorId' => $v['id'],
                'validatorAddress' => $v['address'],
                'type' => self::STAKING_REWARD_TYPES[$this->h('staking|rewardtype|' . $i) % count(self::STAKING_REWARD_TYPES)],
                'amountEth' => $this->intIn(1, 240, 'staking|rewardamt|' . $i) / 10000.0,
                'ageOffsetSeconds' => $this->intIn(600, 4 * 86400, 'staking|rewardage|' . $i),
            ];
        }
        usort($out, static function (array $a, array $b): int {
            return $a['ageOffsetSeconds'] <=> $b['ageOffsetSeconds'];
        });
        return $out;
    }

    /** The deterministic reference an unstake request is assigned — same idiom as wireRef(). */
    public function stakingUnstakeRef(string $slot): string
    {
        return 'UNSTK-' . FrozenClock::year() . '-' . strtoupper(substr(hash('sha256', $this->seed . '|unstake|' . $slot), 0, 6));
    }

    /** A large seeded exit-queue position — always deep enough to read as a genuine backlog. */
    public function stakingUnstakeQueuePosition(): int
    {
        return $this->intIn(800, 4200, 'staking|queuepos');
    }

    /** A seeded estimated exit wait, in days. */
    public function stakingUnstakeWaitDays(): int
    {
        return $this->intIn(9, 46, 'staking|waitdays');
    }

    /** Why the unstake request reads as failed — deterministic, never a real policy/body name. */
    public function stakingUnstakeFailureReason(): string
    {
        return self::STAKING_UNSTAKE_FAILURE_REASONS[$this->h('staking|failreason') % count(self::STAKING_UNSTAKE_FAILURE_REASONS)];
    }
}
