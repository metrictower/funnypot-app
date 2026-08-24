<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT appliances / AV / elevators plane for the deep office/BMS panel — the operator's
 * "it does everything" whimsy (spec §C.9). Sits on Building (the coherence spine): every coffee machine
 * and kitchen appliance lives in a real Kitchen room, every signage screen in a real Reception/common
 * room, and every elevator car serves the building's real floor stack, so the same site an attacker sees
 * in HVAC/Access reconciles here too.
 *
 * Design rules (deep-admin dashboard spec §C.9 + adversarial critique):
 *  - DETERMINISTIC per seed: every reading is hash(seed+entityId+field) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); an entity's facts are derived from its id alone, so machine($id) is
 *    byte-identical to that machine's row in the list and reproducible standalone. Ages/dates come from
 *    FrozenClock, the one frozen "now" every module shares.
 *  - COHERENT: kitchens/rooms derive from Building; a machine names a real room, floor label and zone; an
 *    elevator car reports a real floor code; counts reconcile with the site.
 *  - SAFE: controller addressing is RFC1918 only — IoT appliance gateway 10.0.55.x, AV/signage/PA
 *    10.0.80.x, elevator group controller 10.0.90.x. Invented model/track/product names only, never a real
 *    trademark or a scanner-signature string. The vending payment tab shows a fixed test-card mask.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/named-args/str_contains/
 *    constructor promotion) so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Appliances
{
    /** Frozen "now" so a static reload is not a tell. Matches Building/Hvac/Org. */
    public const DEPLOY_EPOCH = FrozenClock::EPOCH;

    /** IoT/AV/lift OT fabric hosts (RFC1918 only). */
    public const IOT_GATEWAY = '10.0.55.10';
    public const AV_CONTROLLER = '10.0.80.10';
    public const LIFT_CONTROLLER = '10.0.90.10';

    /** @var int */
    private $seed;

    /** @var Building */
    private $bld;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
        $this->bld = Building::fromSeed($seed);
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|appl|' . $salt), 0, 15));
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

    /** vN.N.N firmware string, frozen per component. */
    private function firmware(string $salt): string
    {
        return 'v' . $this->intIn(1, 5, $salt . '|fa')
            . '.' . $this->intIn(0, 18, $salt . '|fb')
            . '.' . $this->intIn(0, 40, $salt . '|fc');
    }

    /** Seeded "N ago" string — pure hash(seed+slot), deterministic, never time()/date(). */
    private function ageAgo(string $salt): string
    {
        $sec = $this->intIn(20, 172800, $salt);
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

    /** A frozen calendar date $daysBack before the frozen "now". */
    private function dateDaysBack(int $daysBack): string
    {
        return FrozenClock::ymdFromDays(FrozenClock::nowDays() - $daysBack);
    }

    /**
     * The building's real floor codes (B1..G..Roof), so an elevator trip log only ever names floors that
     * exist for this seed — a ghost floor an attacker can't find in the site would unmask the page.
     *
     * @return list<string>
     */
    public function floorCodes(): array
    {
        $codes = [];
        foreach ($this->bld->floors() as $f) {
            $codes[] = (string) $f['code'];
        }
        return $codes;
    }

    // --- kitchens (the Building rooms coffee/vending/kitchen appliances live in) ---

    /**
     * Real Kitchen rooms across the building (coherence spine). A fallback anchors at least one so the
     * coffee/kitchen surface always exists even on a seed whose room mix happens to hold no Kitchen.
     *
     * @return list<array{id:string,name:string,floor:string,floorLabel:string,zone:string}>
     */
    public function kitchens(): array
    {
        $out = [];
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if ($r['type'] === 'Kitchen') {
                    $out[] = [
                        'id' => $r['id'],
                        'name' => $r['name'],
                        'floor' => $r['floor'],
                        'floorLabel' => $f['label'],
                        'zone' => $r['zone'],
                    ];
                }
            }
        }
        if ($out !== []) {
            return $out;
        }
        // Fallback: the first room on the ground (or lowest) floor so the lure never disappears.
        foreach ($this->bld->floors() as $f) {
            $rooms = $this->bld->roomsFor($f['code']);
            if ($rooms !== []) {
                $r = $rooms[0];
                return [[
                    'id' => $r['id'],
                    'name' => $r['name'] . ' (Kitchenette)',
                    'floor' => $r['floor'],
                    'floorLabel' => $f['label'],
                    'zone' => $r['zone'],
                ]];
            }
        }
        return [['id' => 'room-g-01', 'name' => 'Ground Kitchen', 'floor' => 'G', 'floorLabel' => 'Ground', 'zone' => 'Core']];
    }

    // --- coffee machines (per-kitchen; brew-boiler temp with a setpoint control) ---

    /** @return list<array<string,mixed>> */
    public function coffeeMachines(): array
    {
        $out = [];
        $seq = [];
        foreach ($this->kitchens() as $k) {
            $fslug = strtolower($k['floor']);
            $n = 1 + ($this->h('coffn|' . $k['id']) % 2); // 1-2 per kitchen
            for ($i = 0; $i < $n; $i++) {
                if (!isset($seq[$fslug])) {
                    $seq[$fslug] = 0;
                }
                $seq[$fslug]++;
                $id = 'coffee-' . $fslug . '-' . sprintf('%02d', $seq[$fslug]);
                $out[] = $this->buildCoffee($id, $k);
            }
        }
        return $out;
    }

    /** One coffee machine by id (known -> real; unknown -> synthesised against the first kitchen), never null. @return array<string,mixed> */
    public function coffee(string $id): array
    {
        foreach ($this->coffeeMachines() as $m) {
            if ($m['id'] === $id) {
                return $m;
            }
        }
        $k = $this->kitchens()[0];
        return $this->buildCoffee($id, $k);
    }

    /**
     * @param array{id:string,name:string,floor:string,floorLabel:string,zone:string} $k
     * @return array{id:string,name:string,model:string,blend:string,kitchenId:string,kitchenName:string,
     *   floor:string,floorLabel:string,zone:string,boilerTemp:int,setpoint:int,tempMin:int,tempMax:int,
     *   beanPct:int,waterPct:int,milkPct:int,cupsToday:int,cupsTotal:int,descaleStatus:string,
     *   descaleInDays:int,lastBrew:string,state:string,firmware:string,gatewayIp:string}
     */
    private function buildCoffee(string $id, array $k): array
    {
        $models = ['Orion', 'Lumen', 'Corvo', 'Halcyon', 'Verona', 'Aurora', 'Cascade'];
        $series = ['S2', 'X3', 'Pro', 'Duo', 'Compact'];
        $blends = ['House Dark', 'Morning Rio', 'Velvet Decaf', 'Highland Blend', 'Espresso Nero', 'Fairtrade Gold'];
        $setpoint = $this->intIn(85, 96, $id . '|sp');
        // Boiler tracks the setpoint within a tight band so the reading and the control never disagree.
        $temp = $setpoint + ($this->h($id . '|tdelta') % 5 - 2);
        if ($temp < 80) {
            $temp = 80;
        }
        if ($temp > 98) {
            $temp = 98;
        }
        $descaleInDays = $this->intIn(-6, 70, $id . '|descale');
        if ($descaleInDays < 0) {
            $descaleStatus = 'Overdue';
        } elseif ($descaleInDays < 7) {
            $descaleStatus = 'Due soon';
        } else {
            $descaleStatus = 'OK';
        }
        $model = $this->pick($models, $id . '|model') . ' ' . $this->pick($series, $id . '|series');
        return [
            'id' => $id,
            'name' => $k['floorLabel'] . ' — ' . $k['name'] . ' · ' . $model,
            'model' => $model,
            'blend' => $this->pick($blends, $id . '|blend'),
            'kitchenId' => $k['id'],
            'kitchenName' => $k['name'],
            'floor' => $k['floor'],
            'floorLabel' => $k['floorLabel'],
            'zone' => $k['zone'],
            'boilerTemp' => $temp,
            'setpoint' => $setpoint,
            'tempMin' => 85,
            'tempMax' => 96,
            'beanPct' => $this->intIn(4, 100, $id . '|bean'),
            'waterPct' => $this->intIn(15, 100, $id . '|water'),
            'milkPct' => $this->intIn(0, 100, $id . '|milk'),
            'cupsToday' => $this->intIn(0, 180, $id . '|cupsd'),
            'cupsTotal' => $this->intIn(9000, 240000, $id . '|cupst'),
            'descaleStatus' => $descaleStatus,
            'descaleInDays' => $descaleInDays,
            'lastBrew' => $this->ageAgo('coffbrew|' . $id),
            'state' => $this->pick(['Ready', 'Ready', 'Ready', 'Standby', 'Heating', 'Rinsing'], $id . '|state'),
            'firmware' => $this->firmware('cofffw|' . $id),
            'gatewayIp' => self::IOT_GATEWAY,
        ];
    }

    // --- vending machines (planogram + chilled temp + cashless payment) ---

    /** @return list<array<string,mixed>> */
    public function vendingMachines(): array
    {
        $out = [];
        $seq = [];
        foreach ($this->kitchens() as $k) {
            // Not every kitchen has a vending machine — roughly two in three.
            if ($this->h('vendhas|' . $k['id']) % 3 === 0) {
                continue;
            }
            $fslug = strtolower($k['floor']);
            if (!isset($seq[$fslug])) {
                $seq[$fslug] = 0;
            }
            $seq[$fslug]++;
            $id = 'vend-' . $fslug . '-' . sprintf('%02d', $seq[$fslug]);
            $out[] = $this->buildVending($id, $k);
        }
        if ($out !== []) {
            return $out;
        }
        // Always keep at least one so the payment goose-chase exists.
        $k = $this->kitchens()[0];
        return [$this->buildVending('vend-' . strtolower($k['floor']) . '-01', $k)];
    }

    /** One vending machine by id, never null. @return array<string,mixed> */
    public function vending(string $id): array
    {
        foreach ($this->vendingMachines() as $m) {
            if ($m['id'] === $id) {
                return $m;
            }
        }
        $k = $this->kitchens()[0];
        return $this->buildVending($id, $k);
    }

    /**
     * @param array{id:string,name:string,floor:string,floorLabel:string,zone:string} $k
     * @return array{id:string,name:string,model:string,kind:string,room:string,floor:string,floorLabel:string,
     *   zone:string,tempC:int,stockPct:int,slotsTotal:int,slotsLow:int,cashboxAmount:string,paymentProvider:string,
     *   cardMask:string,terminalId:string,state:string,lastRefill:string,firmware:string,gatewayIp:string}
     */
    private function buildVending(string $id, array $k): array
    {
        $chilled = $this->h($id . '|chilled') % 2 === 0;
        $models = $chilled
            ? ['ChillVend C9', 'CoolStock XL', 'FreshPoint 5']
            : ['SnackMate 700', 'KioskOne 4', 'PantryBox 12'];
        $slots = $this->planogram($id, $chilled);
        $low = 0;
        $stock = 0;
        foreach ($slots as $s) {
            if ($s['qty'] <= 2) {
                $low++;
            }
            $stock += $s['qty'];
        }
        $capacity = count($slots) * 8;
        $stockPct = $capacity > 0 ? (int) round($stock / $capacity * 100) : 0;
        if ($stockPct > 100) {
            $stockPct = 100;
        }
        // Fixed test-card mask (never a real PAN) — the cashless goose-chase, per spec §C.9.
        $providers = ['NorthPay', 'CashlessOne', 'PayZone Retail', 'Vendix Pay'];
        return [
            'id' => $id,
            'name' => $k['floorLabel'] . ' — ' . $k['name'] . ' vending',
            'model' => $this->pick($models, $id . '|model'),
            'kind' => $chilled ? 'Chilled drinks' : 'Ambient snacks',
            'room' => $k['name'],
            'floor' => $k['floor'],
            'floorLabel' => $k['floorLabel'],
            'zone' => $k['zone'],
            'tempC' => $chilled ? $this->intIn(3, 7, $id . '|temp') : $this->intIn(19, 24, $id . '|temp'),
            'stockPct' => $stockPct,
            'slotsTotal' => count($slots),
            'slotsLow' => $low,
            'cashboxAmount' => number_format($this->intIn(1200, 48000, $id . '|cash') / 100, 2),
            'paymentProvider' => $this->pick($providers, $id . '|prov'),
            'cardMask' => '**** **** **** 4242',
            'terminalId' => 'TERM-' . strtoupper(substr(hash('sha256', $this->seed . '|vendterm|' . $id), 0, 8)),
            'state' => $this->pick(['Online', 'Online', 'Online', 'Door open', 'Payment offline'], $id . '|state'),
            'lastRefill' => $this->dateDaysBack($this->intIn(1, 21, $id . '|refill')),
            'firmware' => $this->firmware('vendfw|' . $id),
            'gatewayIp' => self::IOT_GATEWAY,
        ];
    }

    /**
     * The planogram slot grid for a vending machine — rows A-F, columns 1-6, each with a product,
     * price and remaining quantity. Products are generic categories, never a brand (spec E7).
     *
     * @return list<array{slot:string,product:string,price:string,qty:int,capacity:int}>
     */
    public function planogram(string $id, bool $chilled): array
    {
        $snacks = ['Cereal Bar', 'Trail Mix', 'Salted Crisps', 'Dark Chocolate', 'Oat Cookie',
                   'Rice Cakes', 'Protein Bar', 'Mixed Nuts', 'Fruit Gums', 'Popcorn', 'Pretzels', 'Flapjack'];
        $drinks = ['Sparkling Water', 'Still Water', 'Cola', 'Diet Cola', 'Orange Juice',
                   'Apple Juice', 'Energy Drink', 'Iced Tea', 'Ginger Beer', 'Lemonade', 'Cold Brew', 'Kombucha'];
        $catalog = $chilled ? $drinks : $snacks;
        $rows = ['A', 'B', 'C', 'D', 'E', 'F'];
        $out = [];
        foreach ($rows as $ri => $r) {
            for ($c = 1; $c <= 6; $c++) {
                $slot = $r . $c;
                $salt = $id . '|slot|' . $slot;
                $product = $catalog[$this->h($salt . '|p') % count($catalog)];
                $price = number_format($this->intIn(80, 320, $salt . '|price') / 100, 2);
                $cap = 8;
                $out[] = [
                    'slot' => $slot,
                    'product' => $product,
                    'price' => $price,
                    'qty' => $this->intIn(0, $cap, $salt . '|qty'),
                    'capacity' => $cap,
                ];
            }
        }
        return $out;
    }

    // --- kitchen appliances (fridge / dishwasher / ice / zip-tap / microwave) ---

    /** @return list<array<string,mixed>> */
    public function kitchenAppliances(): array
    {
        $out = [];
        $seq = [];
        // Each kitchen carries a stable mix of white goods; the mix is seeded but always present.
        $types = ['Fridge', 'Dishwasher', 'Ice machine', 'Boiling-water tap', 'Microwave'];
        foreach ($this->kitchens() as $k) {
            $fslug = strtolower($k['floor']);
            foreach ($types as $ti => $type) {
                // Fridge + boiling tap always present; the rest ~two in three.
                if ($type !== 'Fridge' && $type !== 'Boiling-water tap'
                    && $this->h('applhas|' . $k['id'] . '|' . $type) % 3 === 0) {
                    continue;
                }
                if (!isset($seq[$fslug])) {
                    $seq[$fslug] = 0;
                }
                $seq[$fslug]++;
                $id = 'appl-' . $fslug . '-' . sprintf('%02d', $seq[$fslug]);
                $out[] = $this->buildAppliance($id, $type, $k);
            }
        }
        return $out;
    }

    /** One kitchen appliance by id, never null. @return array<string,mixed> */
    public function appliance(string $id): array
    {
        foreach ($this->kitchenAppliances() as $a) {
            if ($a['id'] === $id) {
                return $a;
            }
        }
        $k = $this->kitchens()[0];
        return $this->buildAppliance($id, 'Fridge', $k);
    }

    /**
     * @param array{id:string,name:string,floor:string,floorLabel:string,zone:string} $k
     * @return array{id:string,type:string,name:string,room:string,floor:string,floorLabel:string,zone:string,
     *   reading:string,setpoint:string,status:string,control:string,state:string,lastService:string,
     *   firmware:string,gatewayIp:string}
     */
    private function buildAppliance(string $id, string $type, array $k): array
    {
        switch ($type) {
            case 'Fridge':
                $sp = $this->intIn(2, 6, $id . '|sp');
                $reading = ($sp + ($this->h($id . '|d') % 3 - 1)) . ' °C';
                $setpoint = $sp . ' °C';
                $status = $this->pick(['Normal', 'Normal', 'Normal', 'Door ajar'], $id . '|st');
                $control = 'temp';
                break;
            case 'Dishwasher':
                $reading = $this->pick(['Idle', 'Idle', 'Running — Eco 50°', 'Running — Intensive', 'Cycle complete'], $id . '|cyc');
                $setpoint = $this->pick(['Eco 50°', 'Auto', 'Intensive 65°', 'Quick 45°'], $id . '|prog');
                $status = $this->pick(['Ready', 'Ready', 'Rinse-aid low', 'Salt low'], $id . '|st');
                $control = 'run';
                break;
            case 'Ice machine':
                $reading = $this->intIn(20, 100, $id . '|bin') . ' % bin';
                $setpoint = 'Cube — full';
                $status = $this->pick(['Producing', 'Producing', 'Bin full', 'Descale due'], $id . '|st');
                $control = 'harvest';
                break;
            case 'Boiling-water tap':
                $reading = $this->intIn(92, 99, $id . '|t') . ' °C';
                $setpoint = '98 °C boiling · 6 °C chilled';
                $status = $this->pick(['Ready', 'Ready', 'Filter 12%', 'CO₂ low'], $id . '|st');
                $control = 'boiling';
                break;
            default: // Microwave
                $reading = 'Idle';
                $setpoint = '—';
                $status = 'Ready';
                $control = '';
                break;
        }
        return [
            'id' => $id,
            'type' => $type,
            'name' => $k['floorLabel'] . ' — ' . $k['name'] . ' · ' . $type,
            'room' => $k['name'],
            'floor' => $k['floor'],
            'floorLabel' => $k['floorLabel'],
            'zone' => $k['zone'],
            'reading' => $reading,
            'setpoint' => $setpoint,
            'status' => $status,
            'control' => $control,
            'state' => $status,
            'lastService' => $this->dateDaysBack($this->intIn(20, 300, $id . '|svc')),
            'firmware' => $this->firmware('applfw|' . $id),
            'gatewayIp' => self::IOT_GATEWAY,
        ];
    }

    // --- elevators (per-car state + the elevator-music sub-tab) ---

    /** @return list<array<string,mixed>> */
    public function elevatorCars(): array
    {
        $n = $this->intIn(3, 6, 'carcount');
        $out = [];
        for ($i = 1; $i <= $n; $i++) {
            $out[] = $this->buildCar('car-' . sprintf('%02d', $i), $i, $n);
        }
        return $out;
    }

    /** One car by id, never null. @return array<string,mixed> */
    public function car(string $id): array
    {
        foreach ($this->elevatorCars() as $c) {
            if ($c['id'] === $id) {
                return $c;
            }
        }
        return $this->buildCar($id, 1, $this->intIn(3, 6, 'carcount'));
    }

    /**
     * @return array{id:string,name:string,letter:string,status:string,currentFloor:string,currentFloorLabel:string,
     *   direction:string,loadPct:int,capacityKg:int,speedMps:string,doorState:string,mode:string,maintenance:bool,
     *   tripsToday:int,lastService:string,nextService:string,vendor:string,vendorPhone:string,fault:string,
     *   controllerIp:string,firmware:string,music:array<string,mixed>}
     */
    private function buildCar(string $id, int $n, int $total): array
    {
        $floors = $this->bld->floors();
        $f = $floors[$this->h($id . '|floor') % count($floors)];
        $modePool = ['Normal', 'Normal', 'Normal', 'Normal', 'Independent service', 'Inspection'];
        $maint = $this->h($id . '|maint') % 6 === 0;
        $mode = $maint ? 'Out of service' : $this->pick($modePool, $id . '|mode');
        $status = $maint ? 'Out of service' : $this->pick(['Idle', 'Idle', 'Moving', 'Doors open'], $id . '|status');
        $dir = $status === 'Moving' ? $this->pick(['Up', 'Down'], $id . '|dir') : 'Stationary';
        $fault = '';
        if ($maint) {
            $fault = $this->pick(['Door operator fault', 'Levelling out of tolerance', 'Overspeed governor test due'], $id . '|fault');
        }
        $vendors = ['Ascentix Lifts', 'VertiCare Service', 'LiftWorks Group', 'Elevon Maintenance'];
        return [
            'id' => $id,
            'name' => 'Car ' . chr(64 + (($n - 1) % 26) + 1),
            'letter' => chr(64 + (($n - 1) % 26) + 1),
            'status' => $status,
            'currentFloor' => $f['code'],
            'currentFloorLabel' => $f['label'],
            'direction' => $dir,
            'loadPct' => $maint ? 0 : $this->intIn(0, 85, $id . '|load'),
            'capacityKg' => $this->pick(['630', '1000', '1275', '1600'], $id . '|cap') + 0,
            'speedMps' => number_format($this->intIn(10, 40, $id . '|speed') / 10, 1),
            'doorState' => $status === 'Doors open' ? 'Open' : 'Closed',
            'mode' => $mode,
            'maintenance' => $maint,
            'tripsToday' => $maint ? 0 : $this->intIn(40, 900, $id . '|trips'),
            'lastService' => $this->dateDaysBack($this->intIn(10, 150, $id . '|svc')),
            'nextService' => $this->dateDaysBack(-$this->intIn(5, 120, $id . '|nsvc')),
            'vendor' => $this->pick($vendors, $id . '|vendor'),
            'vendorPhone' => '+1 555-0' . sprintf('%03d', $this->intIn(100, 899, $id . '|vphone')),
            'fault' => $fault,
            'controllerIp' => self::LIFT_CONTROLLER,
            'firmware' => $this->firmware('carfw|' . $id),
            'music' => $this->buildMusic($id),
        ];
    }

    /**
     * The elevator-music media player for a car (spec §C.9 flagship whimsy): now-playing, a playlist, a
     * volume level and a source. Track/artist names are invented, never real songs (no copyrighted media).
     *
     * @return array{entity:string,state:string,source:string,volumePct:int,playlist:string,playlistFile:string,
     *   nowTrack:string,nowArtist:string,positionSec:int,durationSec:int,tracks:list<array{n:int,title:string,artist:string,length:string}>}
     */
    private function buildMusic(string $id): array
    {
        $tracks = [
            ['Blue Lobby', 'The Waiting Room'],
            ['Soft Transit', 'Otis Vale'],
            ['Ground Floor Bossa', 'Cafe Lumen'],
            ['Atrium Lights', 'Marble & Chrome'],
            ['Nightporter', 'Slow Ascent'],
            ['Mezzanine Dreams', 'The Concierge'],
            ['Escalator Sunrise', 'Foyer Trio'],
            ['Penthouse Rain', 'Gloss'],
            ['Reception Waltz', 'Velvet Rope'],
            ['Service Level', 'Dumbwaiter'],
        ];
        $playlists = ['playlist_lobby', 'playlist_ambient', 'playlist_jazz_am', 'playlist_daytime'];
        $sources = ['Playlist', 'Playlist', 'Internet Radio', 'Aux Input', 'Streaming'];
        $playlist = $this->pick($playlists, $id . '|pl');
        $count = $this->intIn(8, 10, $id . '|trkn');
        $list = [];
        for ($i = 0; $i < $count; $i++) {
            $t = $tracks[($this->h($id . '|trk|' . $i) + $i) % count($tracks)];
            $secs = $this->intIn(122, 268, $id . '|len|' . $i);
            $list[] = [
                'n' => $i + 1,
                'title' => $t[0],
                'artist' => $t[1],
                'length' => sprintf('%d:%02d', intdiv($secs, 60), $secs % 60),
            ];
        }
        $nowIdx = $this->h($id . '|now') % $count;
        $now = $list[$nowIdx];
        $dur = $this->intIn(122, 268, $id . '|nowdur');
        return [
            'entity' => 'media_player.elevator_music_' . str_replace('-', '_', $id),
            'state' => $this->pick(['Playing', 'Playing', 'Playing', 'Paused'], $id . '|mstate'),
            'source' => $this->pick($sources, $id . '|src'),
            'volumePct' => $this->intIn(10, 65, $id . '|vol'),
            'playlist' => $playlist,
            'playlistFile' => $playlist . '.m3u.zip',
            'nowTrack' => $now['title'],
            'nowArtist' => $now['artist'],
            'positionSec' => $this->intIn(5, $dur - 5, $id . '|pos'),
            'durationSec' => $dur,
            'tracks' => $list,
        ];
    }

    // --- digital signage screens ---

    /** @return list<array<string,mixed>> */
    public function signageScreens(): array
    {
        $rooms = $this->publicRooms();
        $out = [];
        $seq = 0;
        foreach ($rooms as $r) {
            // Not every public room has a screen; roughly three in four.
            if ($this->h('signhas|' . $r['id']) % 4 === 0) {
                continue;
            }
            $seq++;
            $out[] = $this->buildScreen('sign-' . sprintf('%02d', $seq), $r);
        }
        if ($out !== []) {
            return $out;
        }
        return [$this->buildScreen('sign-01', $rooms[0])];
    }

    /** One screen by id, never null. @return array<string,mixed> */
    public function signage(string $id): array
    {
        foreach ($this->signageScreens() as $s) {
            if ($s['id'] === $id) {
                return $s;
            }
        }
        return $this->buildScreen($id, $this->publicRooms()[0]);
    }

    /** Total screens on the estate (for the "displayed on N screens" canned line). */
    public function signageCount(): int
    {
        return count($this->signageScreens());
    }

    /**
     * @param array{id:string,name:string,floor:string,floorLabel:string,zone:string} $r
     * @return array{id:string,name:string,room:string,floor:string,floorLabel:string,zone:string,content:string,
     *   orientation:string,resolution:string,power:string,brightnessPct:int,lastSync:string,model:string,
     *   controllerIp:string,firmware:string}
     */
    private function buildScreen(string $id, array $r): array
    {
        $content = ['Welcome / Reception loop', 'Wayfinding — this floor', 'Cafeteria menu',
                    'Company news', 'Meeting-room schedule', 'Health & safety notices', 'Visitor sign-in'];
        $models = ['ViewCast 55', 'Displayr 4K', 'SignStream 43', 'PanelOne 65'];
        return [
            'id' => $id,
            'name' => $r['floorLabel'] . ' — ' . $r['name'] . ' screen',
            'room' => $r['name'],
            'floor' => $r['floor'],
            'floorLabel' => $r['floorLabel'],
            'zone' => $r['zone'],
            'content' => $this->pick($content, $id . '|content'),
            'orientation' => $this->pick(['Landscape', 'Landscape', 'Portrait'], $id . '|orient'),
            'resolution' => $this->pick(['1920×1080', '3840×2160', '1080×1920'], $id . '|res'),
            'power' => $this->pick(['On', 'On', 'On', 'On', 'Standby'], $id . '|power'),
            'brightnessPct' => $this->intIn(45, 100, $id . '|bri'),
            'lastSync' => $this->ageAgo('signsync|' . $id),
            'model' => $this->pick($models, $id . '|model'),
            'controllerIp' => self::AV_CONTROLLER,
            'firmware' => $this->firmware('signfw|' . $id),
        ];
    }

    /**
     * Public/common rooms a screen or PA speaker sits in — Reception first, then a spread of other rooms.
     *
     * @return list<array{id:string,name:string,floor:string,floorLabel:string,zone:string}>
     */
    private function publicRooms(): array
    {
        $out = [];
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if (in_array($r['type'], ['Reception', 'Wellness', 'Kitchen', 'Open-plan'], true)) {
                    $out[] = [
                        'id' => $r['id'],
                        'name' => $r['name'],
                        'floor' => $r['floor'],
                        'floorLabel' => $f['label'],
                        'zone' => $r['zone'],
                    ];
                }
            }
        }
        if ($out !== []) {
            return $out;
        }
        return $this->kitchens();
    }

    // --- PA / paging zones ---

    /**
     * Paging zones — All-call plus one per floor plus a couple of fixed common areas. Volume + speaker
     * count per zone; the broadcast box itself emits nothing (canned receipt).
     *
     * @return list<array{id:string,name:string,speakers:int,volumePct:int,state:string}>
     */
    public function paZones(): array
    {
        $out = [];
        $out[] = $this->buildPaZone('pa-all-call', 'All-call (site-wide)');
        foreach ($this->bld->floors() as $f) {
            $slug = 'pa-floor-' . strtolower($f['code']);
            $out[] = $this->buildPaZone($slug, $f['label']);
        }
        foreach (['Reception', 'Cafeteria', 'Car park'] as $area) {
            $slug = 'pa-' . strtolower(str_replace(' ', '-', $area));
            $out[] = $this->buildPaZone($slug, $area);
        }
        return $out;
    }

    /** One PA zone by id, never null. @return array{id:string,name:string,speakers:int,volumePct:int,state:string} */
    public function paZone(string $id): array
    {
        foreach ($this->paZones() as $z) {
            if ($z['id'] === $id) {
                return $z;
            }
        }
        return $this->buildPaZone($id, ucfirst(str_replace('-', ' ', $id)));
    }

    /** @return array{id:string,name:string,speakers:int,volumePct:int,state:string} */
    private function buildPaZone(string $id, string $name): array
    {
        return [
            'id' => $id,
            'name' => $name,
            'speakers' => $this->intIn(2, 48, $id . '|spk'),
            'volumePct' => $this->intIn(30, 80, $id . '|vol'),
            'state' => $this->pick(['Idle', 'Idle', 'Idle', 'Chime armed'], $id . '|state'),
        ];
    }

    // --- reconciled headline counts for the landing ---

    /**
     * @return array{coffee:int,cupsToday:int,vending:int,vendingLow:int,kitchen:int,cars:int,carsInService:int,
     *   carsFaulted:int,signage:int,signageOn:int,paZones:int,descaleDue:int}
     */
    public function summary(): array
    {
        $coffee = $this->coffeeMachines();
        $cups = 0;
        $descale = 0;
        foreach ($coffee as $m) {
            $cups += (int) $m['cupsToday'];
            if ($m['descaleStatus'] !== 'OK') {
                $descale++;
            }
        }
        $vending = $this->vendingMachines();
        $vendLow = 0;
        foreach ($vending as $v) {
            if ($v['slotsLow'] > 0) {
                $vendLow++;
            }
        }
        $cars = $this->elevatorCars();
        $inService = 0;
        $faulted = 0;
        foreach ($cars as $c) {
            if ($c['maintenance']) {
                $faulted++;
            } else {
                $inService++;
            }
        }
        $screens = $this->signageScreens();
        $on = 0;
        foreach ($screens as $s) {
            if ($s['power'] === 'On') {
                $on++;
            }
        }
        return [
            'coffee' => count($coffee),
            'cupsToday' => $cups,
            'vending' => count($vending),
            'vendingLow' => $vendLow,
            'kitchen' => count($this->kitchenAppliances()),
            'cars' => count($cars),
            'carsInService' => $inService,
            'carsFaulted' => $faulted,
            'signage' => count($screens),
            'signageOn' => $on,
            'paZones' => count($this->paZones()),
            'descaleDue' => $descale,
        ];
    }

    /** Seeded "last gateway poll" freshness for the landing — never time() (spec E11). */
    public function lastPollAge(): string
    {
        return $this->intIn(8, 50, 'iotpoll') . ' s ago';
    }

    /** A deterministic short command id for an inert control receipt. */
    public function commandId(string $salt): string
    {
        return 'AV-CMD-' . strtoupper(substr(hash('sha256', $this->seed . '|applcmd|' . $salt), 0, 8));
    }
}
