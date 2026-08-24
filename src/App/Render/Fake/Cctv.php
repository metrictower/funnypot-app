<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT CCTV estate for the deep office panel — cameras, recordings and NVR arrays that
 * cross-reference the ONE building topology (Building) so a camera sits in a real room, on a real floor,
 * recorded by a real NVR controller, exactly the way it appears everywhere else it is referenced.
 *
 * Design rules (deep-admin dashboard spec §C.4 + adversarial critique):
 *  - COHERENT: room cameras are the same `cam-*` devices Building.devices() places (same id, room, floor,
 *    zone, NVR controller), enriched with CCTV facts (model/resolution/codec/rtsp/retention). A fixed set
 *    of exterior cameras (loading dock, parking gate, lobby ...) is added for the physical-access lures.
 *  - SAFE: all addressing is RFC1918 on the CCTV/NVR fabric (10.0.70.x, matching Building's NVR prefix).
 *    RTSP is an inert bait string that opens no socket. Invented model ids only (spec E7), never a real
 *    trademark and never a scanner-signature string.
 *  - DETERMINISTIC per seed: every value is hash(seed+slot); no time()/date()/rand()/shuffle(). Burned
 *    timecodes derive from one frozen base so a static reload is not a tell (spec E10/E11).
 *  - INERT: nothing here is or drives a real feed; the section renders placeholders and canned controls.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/named-args/str_contains/promotion) so a fact
 *    can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Cctv
{
    /** Frozen "now" base for burned timecodes / recording windows — the one shared clock. */
    public const DEPLOY_EPOCH = FrozenClock::EPOCH;

    /** @var int */
    private $seed;

    /** @var Building */
    private $building;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
        $this->building = Building::fromSeed($seed);
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|cctv|' . $salt), 0, 15));
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

    /**
     * A "just now" instant for a burned timecode — a few seconds to a few minutes before DEPLOY_EPOCH, so
     * a live-view overlay reads as the panel's own clock, not a random hour that can land hours ahead of
     * the frozen "now" (spec E11 — no future timestamps).
     */
    private function liveTimecode(string $salt): string
    {
        $epoch = self::DEPLOY_EPOCH - $this->intIn(0, 240, $salt . '|lag');
        return FrozenClock::ymd($epoch) . ' ' . FrozenClock::clock($epoch);
    }

    // --- catalogs (invented, resemblance only) ---

    /** @return list<string> */
    private function models(): array
    {
        return ['VigilCam VC-4200', 'SentryView SV-8', 'OmniWatch OW-360', 'ClearSight CS-20',
                'NightHawk NH-5', 'ProGuard PG-12', 'Aperion AX-9', 'Warden WD-700'];
    }

    /** @return list<string> */
    private function resolutions(): array
    {
        return ['720p (1280x720)', '1080p (1920x1080)', '4MP (2560x1440)',
                '5MP (2592x1944)', '4K (3840x2160)'];
    }

    // --- cameras ---

    /**
     * The full camera roster: every Building camera device enriched with CCTV facts, followed by the
     * fixed exterior cameras. Stable order (room cameras in Building order, then exterior), so paging is
     * deterministic. Never empty (the exterior set is always present).
     *
     * @return list<array{id:string,name:string,area:string,floor:string,zone:string,room:string,model:string,resolution:string,codec:string,fps:int,ip:string,port:int,rtsp:string,nvr:string,channel:string,status:string,recording:bool,ptz:bool,retentionDays:int,timecode:string}>
     */
    public function cameras(): array
    {
        $out = [];
        $roomIndex = $this->roomIndex();
        $nvrIds = $this->nvrIds();

        foreach ($this->building->devices() as $d) {
            if ($d['domain'] !== 'camera') {
                continue;
            }
            $room = isset($roomIndex[$d['room']]) ? $roomIndex[$d['room']] : null;
            $out[] = $this->enrich(
                $d['id'],
                $this->cameraName($room, $d['floor']),
                $room === null ? 'Interior' : $room['type'],
                $d['floor'],
                $d['zone'],
                $d['room'],
                $d['controller'],
                $d['busAddress'],
                $this->stateFromDevice($d['state'], $d['id'])
            );
        }

        // Exterior/physical-access cameras — the loading dock/parking-gate lures. Not room devices.
        $ext = ['Loading Dock East', 'Loading Dock West', 'Goods Entrance', 'Parking Gate',
                'Executive Lobby', 'Main Reception', 'Perimeter North', 'Perimeter South'];
        $anomIdx = $this->h('extanom') % count($ext); // one planted signal-loss (the footage-gap bait)
        $plantAnom = ($this->h('extanomon') % 2) === 0;
        foreach ($ext as $i => $name) {
            $status = 'online';
            if ($plantAnom && $i === $anomIdx) {
                $status = 'no-signal';
            }
            $out[] = $this->enrich(
                'cam-ext-' . sprintf('%02d', $i + 1),
                $name,
                'Exterior',
                '',
                '',
                '',
                $nvrIds[$i % count($nvrIds)],
                'ch' . ($i + 1),
                $status
            );
        }

        return $out;
    }

    /**
     * One camera by id. A known id returns its enriched record; an unknown/fuzzed id returns a plausible
     * synthesized camera keyed on the slug, so a deep crawl never dead-ends in a 404 (spec D.4). Never null.
     *
     * @return array{id:string,name:string,area:string,floor:string,zone:string,room:string,model:string,resolution:string,codec:string,fps:int,ip:string,port:int,rtsp:string,nvr:string,channel:string,status:string,recording:bool,ptz:bool,retentionDays:int,timecode:string}
     */
    public function camera(string $id): array
    {
        foreach ($this->cameras() as $c) {
            if ($c['id'] === $id) {
                return $c;
            }
        }
        // Plausible synthesis for an unknown slug — same shape, keyed on the id.
        $nvrIds = $this->nvrIds();
        $label = ucwords(str_replace('-', ' ', $id));
        return $this->enrich(
            $id !== '' ? $id : 'cam-unknown',
            $label,
            'Interior',
            '',
            '',
            '',
            $nvrIds[$this->h('synthnvr|' . $id) % count($nvrIds)],
            'ch' . $this->intIn(1, 32, 'synthch|' . $id),
            'online'
        );
    }

    /** Enrich a camera identity with CCTV facts. All addressing on the RFC1918 CCTV fabric (10.0.70.x). */
    private function enrich(
        string $id,
        string $name,
        string $area,
        string $floor,
        string $zone,
        string $room,
        string $nvr,
        string $channel,
        string $status
    ): array {
        $salt = 'cam|' . $id;
        $host = 30 + ($this->h($salt . '|host') % 200); // .30-.229, clear of the NVR controllers
        $ip = '10.0.70.' . $host;
        $retention = $this->retentionFor($nvr);
        return [
            'id' => $id,
            'name' => $name,
            'area' => $area,
            'floor' => $floor,
            'zone' => $zone,
            'room' => $room,
            'model' => $this->pick($this->models(), $salt . '|model'),
            'resolution' => $this->pick($this->resolutions(), $salt . '|res'),
            'codec' => $this->pick(['H.264', 'H.265'], $salt . '|codec'),
            'fps' => $this->pick(['12', '15', '20', '25', '30'], $salt . '|fps') + 0,
            'ip' => $ip,
            'port' => 554,
            'rtsp' => 'rtsp://' . $ip . ':554/live/' . strtolower($channel) . '/main',
            'nvr' => $nvr,
            'channel' => $channel,
            'status' => $status,
            'recording' => $status === 'online' || $status === 'tampering',
            'ptz' => ($this->h($salt . '|ptz') % 3) === 0,
            'retentionDays' => $retention,
            'timecode' => $this->liveTimecode($salt . '|tc'),
        ];
    }

    /** Map a Building device state onto a CCTV status; a "fault" reads as the budgeted tampering bait. */
    private function stateFromDevice(string $state, string $id): string
    {
        if ($state === 'offline') {
            return 'no-signal';
        }
        if ($state === 'fault') {
            return ($this->h('tamper|' . $id) % 2) === 0 ? 'tampering' : 'no-signal';
        }
        return 'online';
    }

    private function cameraName($room, string $floor): string
    {
        if ($room === null) {
            return $floor === '' ? 'Camera' : 'Floor ' . $floor . ' Camera';
        }
        $name = $room['name'];
        switch ($room['type']) {
            case 'Server-Comms':
                return 'Server Room (' . $name . ')';
            case 'Reception':
                return 'Reception (' . $name . ')';
            case 'Exec':
                return 'Executive (' . $name . ')';
            case 'Lab':
                return 'Lab (' . $name . ')';
            default:
                return $name . ' (Floor ' . $room['floor'] . ')';
        }
    }

    /** room id => room record, across every floor (for camera cross-reference). */
    private function roomIndex(): array
    {
        $index = [];
        foreach ($this->building->floors() as $f) {
            foreach ($this->building->roomsFor($f['code']) as $r) {
                $index[$r['id']] = $r;
            }
        }
        return $index;
    }

    // --- recordings ---

    /**
     * Seeded recording clips for a camera, newest first. Row $i's start walks strictly backward from
     * DEPLOY_EPOCH by the clip's own duration plus a seeded gap, the same anchoring events()/
     * cameraEventsFor() use, so a clip never "starts" later than the frozen now and the reel reads as
     * one continuous back-catalogue rather than a wall clock stuck in the future (spec E11). Filenames
     * end `.mp4.zip` so a download routes to the decoy-archive handler (spec E8), and match
     * [A-Za-z0-9._-] so the section can link them.
     *
     * @return list<array{file:string,start:string,duration:string,size:string,trigger:string}>
     */
    public function recordings(string $camId): array
    {
        $count = $this->intIn(6, 14, 'recn|' . $camId);
        $triggers = ['Continuous', 'Motion', 'Motion', 'Alarm', 'Tamper', 'Line-cross'];
        $out = [];
        $epoch = self::DEPLOY_EPOCH;
        for ($i = 0; $i < $count; $i++) {
            $salt = 'rec|' . $camId . '|' . $i;
            $secs = $this->intIn(20, 1800, $salt . '|dur');
            $mb = $this->intIn(40, 2400, $salt . '|mb');
            $epoch -= ($secs + $this->intIn(60, 3600, $salt . '|gap'));
            $ymd = FrozenClock::ymd($epoch);
            $hhmm = substr(FrozenClock::clock($epoch), 0, 5);
            $out[] = [
                'file' => $camId . '_' . str_replace('-', '', $ymd)
                    . '_' . str_replace(':', '', $hhmm) . '.mp4.zip',
                'start' => $ymd . ' ' . FrozenClock::clock($epoch),
                'duration' => $this->durationLabel($secs),
                'size' => $mb < 1024 ? $mb . ' MB' : number_format($mb / 1024, 1) . ' GB',
                'trigger' => $triggers[$this->h($salt . '|trig') % count($triggers)],
            ];
        }
        return $out;
    }

    private function durationLabel(int $secs): string
    {
        if ($secs < 60) {
            return $secs . 's';
        }
        return (int) ($secs / 60) . 'm ' . ($secs % 60) . 's';
    }

    // --- NVR arrays ---

    /** @return list<string> the NVR controller ids from the shared building topology. */
    private function nvrIds(): array
    {
        $ids = [];
        foreach ($this->building->controllers() as $c) {
            if ($c['kind'] === 'NVR') {
                $ids[] = $c['id'];
            }
        }
        return $ids === [] ? ['NVR-01'] : $ids;
    }

    private function retentionFor(string $nvr): int
    {
        return $this->pick(['14', '30', '30', '45', '60', '90'], 'ret|' . $nvr) + 0;
    }

    /**
     * The NVR recorder arrays (from Building's NVR controllers), each with capacity, camera load and
     * retention. usedTb < totalTb by construction so the storage bar always reconciles.
     *
     * @return list<array{id:string,model:string,ip:string,protocol:string,health:string,totalTb:int,usedTb:float,cameras:int,retentionDays:int}>
     */
    public function nvrArrays(): array
    {
        $counts = array();
        foreach ($this->cameras() as $c) {
            $counts[$c['nvr']] = (isset($counts[$c['nvr']]) ? $counts[$c['nvr']] : 0) + 1;
        }
        $out = [];
        foreach ($this->building->controllers() as $c) {
            if ($c['kind'] !== 'NVR') {
                continue;
            }
            $total = (int) $this->pick(['24', '36', '48', '72', '96'], 'nvrtb|' . $c['id']);
            $usedPct = $this->intIn(35, 92, 'nvruse|' . $c['id']);
            $out[] = [
                'id' => $c['id'],
                'model' => $this->pick(['StoreVault NVR-64', 'ArrayGuard AG-32', 'DeepStore DS-128'], 'nvrmodel|' . $c['id']),
                'ip' => $c['ip'],
                'protocol' => $c['protocol'],
                'health' => $c['health'],
                'totalTb' => $total,
                'usedTb' => round($total * $usedPct / 100, 1),
                'cameras' => isset($counts[$c['id']]) ? $counts[$c['id']] : 0,
                'retentionDays' => $this->retentionFor($c['id']),
            ];
        }
        return $out;
    }

    // --- events + summary ---

    /**
     * Recent camera-plane events (newest first) — motion / tamper / signal-loss lines for the landing and
     * per-camera log. Each row walks strictly backward from DEPLOY_EPOCH by a seeded positive gap, so the
     * date advances (never repeats or jumps) exactly when the walk crosses midnight, and row 0 is never
     * later than "now" (spec E11 — no future timestamps).
     *
     * @return list<string>
     */
    public function events(int $count): array
    {
        if ($count < 0) {
            $count = 0;
        }
        $cams = $this->cameras();
        $kinds = ['MOTION', 'MOTION', 'LINE-CROSS', 'TAMPER', 'SIGNAL-LOSS', 'PTZ-PRESET', 'RECORD-START'];
        $out = [];
        $epoch = self::DEPLOY_EPOCH;
        for ($i = 0; $i < $count; $i++) {
            $salt = 'evt|' . $i;
            $cam = $cams[$this->h($salt . '|cam') % count($cams)];
            $kind = $kinds[$this->h($salt . '|kind') % count($kinds)];
            $epoch -= $this->intIn(20, 240, $salt . '|gap');
            $out[] = FrozenClock::ymd($epoch) . ' ' . FrozenClock::clock($epoch)
                . '  ' . $kind . '  ' . $cam['id'] . '  ' . $cam['name'];
        }
        return $out;
    }

    /**
     * This camera's own recent event tail (newest first) — every line names THIS camera, so a per-camera
     * events tab never shows another camera's id. Same strictly-backward walk off DEPLOY_EPOCH as events(),
     * keyed to (camId,index), so no row is ever in the future and the date advances only forward-in-time.
     *
     * @return list<string>
     */
    public function cameraEventsFor(string $camId, int $count): array
    {
        if ($count < 0) {
            $count = 0;
        }
        $cam = $this->camera($camId);
        $kinds = ['MOTION', 'MOTION', 'LINE-CROSS', 'TAMPER', 'SIGNAL-LOSS', 'PTZ-PRESET', 'RECORD-START'];
        $out = [];
        $epoch = self::DEPLOY_EPOCH;
        for ($i = 0; $i < $count; $i++) {
            $salt = 'camevt|' . $camId . '|' . $i;
            $kind = $kinds[$this->h($salt . '|kind') % count($kinds)];
            $epoch -= $this->intIn(30, 300, $salt . '|gap');
            $out[] = FrozenClock::ymd($epoch) . ' ' . FrozenClock::clock($epoch)
                . '  ' . $kind . '  ' . $cam['id'] . '  ' . $cam['name'];
        }
        return $out;
    }

    /** Seeded depth of the event buffer for the landing pager — varies per deploy, never a fixed tell. */
    public function eventBufferTotal(): int
    {
        return 40000 + ($this->h('eventtotal') % 80000);
    }

    /**
     * Reconciled headline counts for the landing tiles.
     *
     * @return array{total:int,online:int,offline:int,recording:int,nvrCount:int,capacityTb:int,usedTb:float}
     */
    public function summary(): array
    {
        $cams = $this->cameras();
        $online = 0;
        $offline = 0;
        $recording = 0;
        foreach ($cams as $c) {
            if ($c['status'] === 'online') {
                $online++;
            }
            if ($c['status'] === 'no-signal' || $c['status'] === 'offline') {
                $offline++;
            }
            if ($c['recording']) {
                $recording++;
            }
        }
        $capacity = 0;
        $used = 0.0;
        $nvrs = $this->nvrArrays();
        foreach ($nvrs as $n) {
            $capacity += $n['totalTb'];
            $used += $n['usedTb'];
        }
        return [
            'total' => count($cams),
            'online' => $online,
            'offline' => $offline,
            'recording' => $recording,
            'nvrCount' => count($nvrs),
            'capacityTb' => $capacity,
            'usedTb' => round($used, 1),
        ];
    }
}
