All facts confirmed against the code (`password_hash` at `AdminLteSkin.php:223`; decoy map matches only `.tar.gz/.tgz/.gz/.zip`; helpers `esc/tableHtml/navHtml/navBase/statCardsHtml/kvTableHtml/downloadTableHtml/preScrollHtml`; `viewFor` at :112, `matches` at :40, `sectionFor` at :158; app = PHP 8.0, core = PHP 7.3). Here is the merged spec.

# Deep office admin dashboard — design spec

**Status:** buildable design, merged from six module brainstorms (facilities, security/life-safety, IoT amenities, energy/BMS, HR, finance, IT/comms), the HomeAssistant-mining breadth study, the UI/IA routing study, and the adversarial critique. Every critique fix (T1–T7, S1–S6, F1–F6) is folded in as a normative rule, not an option.

**Ground truth verified in-repo (2026-08-24):**
- App `metrictower/funnypot` requires **PHP >= 8.0**; `metrictower/funnypot-core` requires **PHP >= 7.3**. Skins and `Funnypot\App\Render\Fake\*` live in the **app**, so they may use 8.0 syntax. Only push a fact into core (7.3-clean) when a core template needs it.
- `AbstractSkin` helpers present: `esc()`, `tableHtml()`, `navHtml()`, `navHref()` (private, slugifies to `[a-z0-9-]`), `navBase()`, `statCardsHtml()`, `kvTableHtml()`, `downloadTableHtml()`, `preScrollHtml()`.
- `AdminLteSkin`: `matches()` @40 (claims `admin|dashboard|manage|panel|console|cp|administrator`), `viewFor()` @112 uses **last segment only** (`end($segs)`), `sectionFor()` @158, `filesCard()` download links route via `navBase . '/files/download/<name>'`.
- **T1 confirmed:** `lootCard()` renders a raw `password_hash` column at **`AdminLteSkin.php:223`**, composed onto the dashboard view (@179). Must move.
- **S1 confirmed:** `HoneypotController::serveDecoyArchive()` (@259) matches **only** `.tar.gz/.tgz/.gz/.zip` and fires only when the engine returns no response. Any other extension will render an HTML admin page instead of a file → Content-Type tell.

---

## A. Vision + the "hours of exploration" principle

### A.1 The product fiction

One login — **"Meridian OneControl"** (product name seeded per deploy from vocab, never a real trademark) — that claims to run *the whole company and the whole building*: HR, finance, IT estate, and a HomeAssistant-grade building-management plane (lighting, HVAC, locks, CCTV, fire, elevators, energy, appliances). The "it does everything" framing is the license for the breadth. An attacker who lands here believes they can drain an account, redirect a vendor wire, pop the server-room door, disarm the alarm, or cut the building's power — and spends hours proving to themselves that they can't, without ever concluding the site is fake.

### A.2 How "hours" is manufactured (the three multipliers)

1. **Breadth** — ~45 sections across 5 module groups, the building side mined from HomeAssistant's ~40 entity domains so no controllable/observable thing is missing.
2. **Depth** — every section follows one 5-rung ladder: `module landing → list → entity detail → sub-tabs → control leaf`. Every page emits 5–15 fresh deeper links; the navigation graph has no leaves.
3. **Cross-linking** — one seed = one company: the same person is a badge-holder, desk-owner, booking-organizer, payslip line, and audit actor; the same `10.0.50.x` controller appears in HVAC points, a camera stream, the ACS, and the fire panel. Following a chain end-to-end and finding it internally consistent is what converts curiosity into trust, and trust into sunk cost.

### A.3 The four load-bearing invariants (every module obeys)

- **INERT.** No control changes any real or logical state. A control is an `<a>`/`<form>` that lands on a canned confirmation. Nothing physical, nothing persisted, nothing outbound (no SMTP, no notify/TTS, no webhook, no AbuseIPDB from fake data). Life-safety verbs never return "done."
- **DETERMINISTIC per deploy.** Every value is `hash(seed + slot)` → vocab index or `[min,max]`. **No `time()`/`date()`/`rand()`/`mt_rand()`/`shuffle()`** in any generator. "Now"/ages derive from one frozen `deployEpoch` constant, monotonic within a page. Same URL → byte-identical page, cacheable forever.
- **SAFE.** All IPs RFC1918 or TEST-NET (`198.51.100.0/24`, `203.0.113.0/24`). All secrets masked at rest and inert on reveal; all PII fabricated and invalid-format. No real product markup/CSS/logos (resemblance only). No scanner-signature strings (invented ids only; never nuclei matcher words or CRS rule ids/`msg`).
- **COHERENT.** Counts reconcile, arithmetic closes, one topology/roster/IP fabric shared across every module. Divergence is a tell.

---

## B. Module map + grouped sidebar IA

### B.1 One skin, one mount, positional routing

**Decision (critique F2/F3): build ONE deep panel skin + per-module section renderers + shared master generators. Do NOT build separate FinancePortalSkin/FacilitiesSkin** — separate skins fragment the single seed/roster/IP fabric that every coherence invariant depends on and create matcher-precedence bugs.

Replace `viewFor()`'s `end($segs)` with a new positional parser:

```
Funnypot\App\Render\PanelRoute::parse(string $path): array
  → ['module','section','entity','subtab','action','arg','page','filter']
```

Route grammar, rooted at the mount (`admin|dashboard|manage|panel|console|cp|administrator`, already claimed by `matches()`):

```
/{mount}/{module}/{section}/{entity}/{subtab}[/{action}/{arg}]
        └ level1  └ level2  └ level3  └ level4  └ control leaf
```

Rules:
- Strip up to and including the first mount token (reuse `PathSegments::startsWithSegmentThenMore`); take positional slots.
- **Every slot slugified to `[a-z0-9-]`** (same guarantee `navHref` gives) → attacker-controlled path is structurally inert as HTML and as href; carries no scheme/quote/`//host`.
- **Pagination + filters live in the path, not query strings**: `.../employees/p7`, `.../employees/dept-finance/p2`. `PanelRoute` peels trailing `p<digits>` into `page`. Keeps cache key = path. If the app forwards a query string, it is display-only, slugified before echo, never routes.
- **Unknown module → Dashboard** (safe fallback). **Unknown section → module list. Unknown entity id → still render a plausible detail page** (see D.4). A 404-inside-a-deep-panel is a tell.
- Keep `AdminLteSkin` (now the one deep skin) registered **last** so `/admin/*` is not stolen by narrower skins.
- **Optional root-mount reach:** if the operator wants `/finance/*`, `/iot/*`, `/hr/*` reachable at root (not only under `/admin/*`), add those tokens to `matches()` — do **not** spawn dedicated skins.

### B.2 The grouped sidebar (≈45 sections)

Render group headers as `<details open><summary>` (native zero-JS collapse) or plain always-expanded text. Building side annotated with its HomeAssistant entity-domain lineage so the fake-widget catalog stays exhaustive.

```
OVERVIEW
  Dashboard              /admin                 business metrics only — NO secrets (T1)
  Building Map           /admin/map             SVG floorplan hub (D + §Facilities)
  Activity Feed          /admin/activity        global seeded timeline
  Alerts & Incidents     /admin/alerts

BUILDING · SMART OFFICE            (HomeAssistant domains → office widgets)
  Lighting               /admin/lighting        light, scene, group
  Climate / HVAC         /admin/hvac            climate, humidifier, water_heater
  Blinds & Shades        /admin/shades          cover
  Access & Doors         /admin/access          lock, cover→door, device_tracker, event
  Security & Alarms      /admin/security        alarm_control_panel, binary_sensor, siren
  Fire & Life Safety     /admin/fire            valve→suppression, binary_sensor→smoke, siren, fan
  CCTV / Cameras         /admin/cctv            camera
  Elevators              /admin/elevators       lift + media_player→music
  Energy & Power         /admin/energy          sensor→power, EV, solar, battery, generator, UPS
  Environment / Sensors  /admin/environment     sensor, binary_sensor, air_quality, weather
  Appliances & AV        /admin/appliances      switch, media_player→signage/PA, coffee, printers, vending
  Cleaning Robots        /admin/robots          vacuum, lawn_mower
  Meeting Rooms          /admin/rooms           calendar + occupancy + AV bundle
  Irrigation & Grounds   /admin/grounds         valve, weather, lawn_mower
  Automations & Scenes   /admin/automations     automation, script, scene (+ Traces)

PEOPLE · HR
  Employee Directory     /admin/hr/employees
  Org Chart              /admin/hr/org
  Payroll                /admin/hr/payroll
  Time & PTO             /admin/hr/pto
  Recruiting (ATS)       /admin/hr/recruiting
  Performance            /admin/hr/performance
  Benefits               /admin/hr/benefits
  HR Cases               /admin/hr/cases
  Training / LMS         /admin/hr/training
  Documents / Reports    /admin/hr/documents    → decoy handler

FINANCE
  Dashboard              /admin/finance
  Accounts Payable       /admin/finance/ap
  Accounts Receivable    /admin/finance/ar
  Expenses               /admin/finance/expenses
  Purchase Orders        /admin/finance/po
  Vendors                /admin/finance/vendors
  Bank Accounts          /admin/finance/banks
  Corporate Cards        /admin/finance/cards
  Payroll Runs           /admin/finance/runs
  Budgets                /admin/finance/budgets
  Financial Statements   /admin/finance/statements
  Tax                    /admin/finance/tax
  Approvals              /admin/finance/approvals
  Audit Log              /admin/finance/audit

IT & PLATFORM              (existing infra re-homed here)
  Helpdesk / ITSM        /admin/it/helpdesk
  Assets / CMDB          /admin/it/assets
  Network Devices        /admin/it/network
  VPN                    /admin/it/vpn
  VoIP / Telephony       /admin/it/voip
  Printers / MFPs        /admin/it/printers
  Licenses               /admin/it/licenses
  Endpoints / MDM        /admin/it/mdm
  Email Admin            /admin/it/email
  Certificates           /admin/it/certs
  Users & Roles          /admin/users           existing lootCard, de-tell'd (T1/E)
  API Keys               /admin/keys             existing keysCard
  Servers                /admin/system           existing systemCard
  Backups                /admin/backups          existing backupsCard
  Databases              /admin/databases        existing / hand to PhpMyAdminSkin
  Logs                   /admin/logs             existing logsCard
  Integrations           /admin/integrations

SETTINGS                 /admin/settings
```

---

## C. Per-module specs

Every module reuses the **five-rung ladder** (B / list / detail / sub-tabs / control leaf) and the **one inert-control mechanism** (D.5). Only module-specific entities, fields, controls, and goose-chases are listed below.

### C.0 Shared conventions used by all modules

- **Entity ids are human-readable deterministic slugs**, not opaque ints: `zone-3f-northwest`, `door-b2-srv`, `cam-loadingdock-01`, `emp-1047`, `inv-2026-004821`, `vav-3-14`. Row at index `i` = `hash(seed+module+section+filter+i)` → vocab. Detail facts = `hash(seed+entityId+field)`. Same index → same entity everywhere (cross-links reconcile).
- **Every download link ends `.zip` or `.tar.gz`** (critique S1 — the only extensions `serveDecoyArchive` serves). Name the intent inside: `board_deck_Q2_2026.pdf.zip`, `passport_scan.zip`, `cam-b2-014_20260823_1400.mp4.zip`, `pnair.ovpn.zip`, `nacha_PR-2026-08.ach.zip`, `sw-core-01-config.cfg.zip`. Never emit a bare `.pdf/.csv/.mp4/.pem/.ovpn` link under the panel mount.
- **Anomaly budget (critique T2):** `hash(seed+module)` selects **0–2** planted anomalies per module; most render clean. Never all-anomalies-at-once — a buffet reads as staged.
- **Reveal dummies are per-secret (critique T5):** `hash(seed+keyId)` in the right shape (`sk_live_…EXAMPLE`, `•••• 0000`), never one global `EXAMPLE0000`.
- **Pending copy varies per module (critique T4):** a small phrasing vocab indexed by `hash(seed+module)`; not one universal "applies at next poll ~60s".

---

### C.1 Building Map + Facilities core

**Master generator: `Fake\Building`** — derives once from seed: site (name, address in a doc-safe city, `SITE-01`, timezone, gross area), **floors** (`hash → 4–14` incl. `B2,B1,G,M,1..N,Roof`, each with zones `N/E/S/W/Core` + design capacity), **rooms** (per floor `8–40`, stable naming scheme picked once: mountains/rivers/cities/grid-codes; type ∈ Meeting/Focus/Open-plan/Exec/Lab/Server-Comms/Kitchen/Reception/Wellness/Store/Plant), **devices** (each: id, type, floor, zone, room, controller, bus address, firmware, last-seen, state — counts scale with floors so totals reconcile), **controllers** (`BMS-CTRL-01..06`, `ACS-CTRL-01..02`, `NVR-01..02` with IP on `10.0.50.x`/`10.0.60.x`/`10.0.70.x`, protocol, health pill). This is the coherence spine for all building modules.

**Building Map (`/admin/map`, `/admin/map/floor-3`)** — the centrepiece time-sink. Deterministic SVG floor outline; rooms are `<rect>`/`<polygon>` wrapped in `<a>` to room detail, tinted by a seeded status dot (green occupied / grey vacant / amber fault). Floor selector. **Room aggregate page** fans out into *every* domain touching that room (lights, HVAC zone, lock, cameras, sensors, bookings, occupants). A 6-floor × 20-room building = 120 room pages × ~10 device links each. Overlays (occupancy/climate/energy) are path-toggled (`/admin/map/floor-3/heat`), frozen, framed "cached 30 s". `[Download floor plan]` → `floorplan-L03.pdf.zip`, `[Export CAD]` → `campus-cad-2026.dwg.zip` (decoy).

**Facilities dashboard tiles** (`statCardsHtml`, each a deep link): Occupancy `214/900`, Zones in comfort `38/44`, Open work orders `17`, Active alarms `3`, Energy now `182 kW`, Doors unsecured `2`, Cameras online `46/48`, Rooms free `9/22`.

**Work Orders / PPM / Vendors (`/admin/facilities/work-orders`)** — the fault-chain hub. WO: `WO-2026-004821`, title, linked asset, priority P1–P4, status, assignee (in-house/vendor), SLA, notes thread (`preScrollHtml`), attachments (`quote.pdf.zip`, `method-statement.pdf.zip`). PPM recurring (chiller service, fire-damper drop test, lift inspection, filter change). Cleaning rota + contractor rows (contract no., site-access badge, insurance expiry). **Every planted fault elsewhere links to a WO that ends one step short ("awaiting parts / awaiting contractor", cross-refs "see also FM-2214") — a small seeded graph you can walk for a long time.**

---

### C.2 Lighting / HVAC / Covers / Environment (HA breadth)

**Lighting (`/admin/lighting`)** — entity = luminaire group. Fields: `light.f3_east_open_plan`, brightness 0–255, `color_temp_kelvin` 2200–6500, `rgb_color`, `effect`, scene, wattage, occupancy-linked, daylight-harvest, DALI/KNX address, lamp-hours `8,412/50,000`, controller. List: `Zone|Floor|State|Bright|CCT|Scene|W|Occupancy|[Detail]`, summary bar `On 118 · Off 214 · Fault 3 · 41.2 kW`. Detail: brightness slider, CCT slider, RGB swatches, scene `<select>`, "apply to whole floor". Sub-tabs: schedule / history (`preScrollHtml`) / energy / wiring. Controls → receipt "142 fixtures queued". Goose-chase: "After-hours" + "maintenance override" ("leave the building dark") — pure fantasy; `light.server_room_uv_sterilizer` / `light.datacenter_row_a`.

**HVAC (`/admin/hvac`)** — entity = zone/VAV/AHU/chiller/boiler/CRAC. HA-accurate fields: `current_temperature`, `temperature` (setpoint), `hvac_mode` (off/heat/cool/heat_cool/auto/dry/fan_only), `hvac_action`, `fan_mode`, `preset_mode`, `current_humidity`, `co2` (420–1400; >1000 = "stuffy" bait), damper %, valve %, filter status, runtime, BACnet `points` (AI/AV/BV object ids), controller `10.0.50.13:47808`. Detail: thermostat dial + gauge + 24h sparkline. Sub-tabs: trends / schedule / alarms / **points** (raw BACnet list — recon bait) / maintenance. **Cross-link flagship:** `climate.server_room_crac_1` cools `Server/Comms 03-Core` where the `10.0.50.x` controllers live → attacker realizes "the BMS controls the temperature of the servers", fantasizes cooking the DB box; the "set 30°C / off" lever is inert. Chiller/boiler P&ID SVG with dozens of clickable points = bottomless.

**Covers (`/admin/shades`)** — `cover` domain: roller/venetian/blackout/skylight/awning/operable-window/garage/loading-dock/parking-barrier. `current_position` 0–100, tilt, wind-lockout, battery %. Open/Close/Stop + position/tilt sliders → receipts. Loading-dock + parking-gate = physical-access bait.

**Environment / Sensors (`/admin/environment`)** — the HA long tail, cheapest breadth (hundreds of read-only rows + one gauge widget = Netdata-style scroll). Mine **every `binary_sensor` device class** (door/window/motion/occupancy/smoke/gas/CO/heat/moisture/vibration/tamper/sound/connectivity/battery/problem/running/safety/update) and **every `sensor` device class with correct HA units** (temperature °C, humidity %, `carbon_dioxide` ppm, pm25/pm10 µg/m³, VOC, illuminance lx, sound dBA, pressure hPa, power W, energy kWh, current A, voltage V, water L, gas m³, signal_strength dBm, wind, uptime, monetary). One planted `binary_sensor.server_room_leak = Wet` (budgeted) → work order. Detail: gauge card + statistics card + history sub-tab (seeded sparkline). No controls (read-only) — depth via count.

---

### C.3 Access Control (physical) — flagship lure #1

Consolidates `lock` + badge/ACS + access-events. **Build first (see F).**

**Door/reader list (`/admin/access`)** — `door-b2-srv`, name (`Server Room A`), type (maglock/strike/mortise/turnstile/barrier/elevator-floor-lock), state (Secured/Held-open/Forced), mode (Card only / Card+PIN / Unlocked office-hours / Lockdown / Free-egress), last event. Include planted rows within budget: `DOOR-DOCK-3 Forced (alarm) 02:41`, `DOOR-14-EXEC Held open`.

**Door detail (`/admin/access/door-b2-srv`)** — state, controller/loop address (`ACS-CTRL-01`, Wiegand/OSDP), REX/DPS, schedule (auto-unlock 07:00–19:00), who-has-access list, recent transactions (`preScrollHtml`), anti-passback, **camera cross-link** (`View on CAM-B2-014`). **Controls:** Unlock / Momentary pulse / Hold-unlocked / Lock / Set mode / Lockdown-floor / Grant-temporary. Building-wide `LOCKDOWN ALL` / `Unlock all (fire egress)` at top. **Soft-deny on the sensitive verbs (this is the key trick):** `Unlock Server Room → DENIED — dual-authorization required (Security + Facilities). Request FAC-CMD-8F3A21 routed to Security desk.` Failure burns *more* time than success — the attacker hunts the second approver / higher privilege that does not exist.

**Cardholders / badges** — `badge_id | holder | dept | access_level (Employee/Contractor/Executive/Facilities/SERVER-ROOM/MASTER) | status (Active/Lost/Expired) | last_seen door/time | pin (masked)`. Count derived from roster (see C.5 ratios), not 50,000. Planted baits (within budget, so usually only ONE of these): a `MASTER 00001` all-doors badge, a lost-but-active badge, an after-hours contractor. `Export cardholders → cardholders_2026-08.csv.zip`.

**Access-events log** (`preScrollHtml`, seeded gradient off `deployEpoch`): `14:07:22 GRANTED Badge 004821 (P. Nair) Door 03-E-01 Server Room`, `03:11:40 DENIED (schedule)`, `02:58 FORCED OPEN — Loading bay B1`, anti-passback violations. One buried off-hours GRANTED to the server room (budgeted).

---

### C.4 Security, Fire & Life-Safety, CCTV — flagship lure #2

**Master generator: `Fake\Safety`** (fire panel, suppression, sprinkler zones, detectors, emergency lighting, intrusion panel/partitions). **`Fake\Cctv`** (roster, config, recordings, NVR arrays). **`Fake\Sensors`** feeds zones (shares C.2 sensors).

**Intrusion Panel (`/admin/security`)** — `alarm_control_panel` domain. Panel status (`Armed-Away`, AC present, battery 13.6V, dual-path comms, one planted trouble `RF jam Zone 9`). Partitions (Office/Warehouse/Vault) with Arm-Home/Away/Night/Disarm/Bypass. **Fake keypad:** any code submitted → canned `Disarm accepted — Partition 1 disarming (exit/entry delay 30s)…` → `Awaiting panel confirmation` — **never fully confirms, never validates a code** (treat like the login oracles that never authenticate; PIN is never reflected — critique S6/T6). Event buffer (`preScrollHtml`).

**Fire & Life-Safety (`/admin/fire`)** — the dangerous-looking crown jewel; must *look* lethal, do *absolutely nothing*. Fire panel status (`NORMAL · Loops 4 · 512/512 devices · battery 27.1V`). Suppression table per space (`Server Room A — FM-200 — ARMED — cylinders 2/2 — 45.2 kg`, `Records Vault — Novec 1230`, `Kitchen — wet chemical`, `Parking — pre-action`). Sprinkler zones, emergency lighting (`46/46 exit signs`, `2 luminaires in fault` — budgeted), smoke-control/HVAC interlock, SLC detector loop (255 addresses = long inert list). **Controls — graduated guarding:**
- Scariest (`Disable suppression`, `Manual release`, `Disarm`) → **two-step**: red warning card + fake operator-PIN field (PIN never validated, never reflected) → `Command CMD-3f9a12e0 queued. Awaiting fire-panel controller ACK. Suppression state unchanged until panel confirms (safety interlock).` The **interlock wording is the alibi** for why state never flips and reads as authentic fire-code behavior.
- Milder (`Trigger Fire Drill`, `Silence`, `Reset`, `Lamp test`) → pending receipt (`Drill scheduled — occupants NOT notified in test mode; sounders in silent test`).
- **No life-safety verb ever returns "done/activated"** (critique S6). Any fault degrades to plain 404, never 500 (invariant #2).

**CCTV (`/admin/cctv`)** — grid of camera tiles, each an **inline-SVG placeholder** (grey frame, camera name, burned timecode `2026-08-23 14:07:42`, `● REC`, ~5% `NO SIGNAL`) — **never `<img src>`, never a real feed/socket** (critique S5, also CSP-clean). Fields: `cam-b2-014`, name (`Server Room A`, `Loading Dock East`, `Executive Lobby`), model (invented, or real brand paired with invented build per T7), resolution, codec, IP `10.0.60.x`, `rtsp://10.0.60.21:554/Streaming/Channels/101` (inert bait string), status, PTZ, retention, NVR `NVR-01 18.2/24 TB`. Detail: big placeholder + PTZ pad (`/ptz/up` → canned), presets (`Server rack row`, `Parking gate`), `[Download clip] → cam-b2-014_...mp4.zip`, sub-tabs live/recordings/settings/nvr. Goose-chases: RTSP+NVR pivot bait; offline camera at the loading bay cross-refs the "door open" status ("the one door I can use has no camera"). Planted `Tampering — footage gap 02:14–02:53` (budgeted) → Incident Log.

**Incident Log (`/admin/alerts`)** — the connective tissue. `INC-2026-00847 | time | type | location | source (device link) | severity | status | guard | actions`. Pager `Showing 1–50 of 41,208` (render page N only, `hash(seed+N)`). Per-incident: timeline, linked clip/door/sensor, `Generate report → incident-847.pdf.zip`. **If the anomaly budget planted the camera gap + the bypassed sensor + the off-hours badge, one incident ties them into a narrative the attacker reconstructs — that leads nowhere.**

---

### C.5 HR portal — the PII gold-mine illusion

**Master generator: `Fake\Org`** — one roster of `N = hash(seed)%180 + 90` (~90–270 people). Derives ids `emp-1001..emp-(1000+N)`, names (40 forename × 40 surname combinator from §C.6), emails `first.last@<domain>`, a **derived manager tree** (`manager(emp-N) = bucket-parent`, so directory column + profile "reports to" + org-chart edges always agree), department, salary band. **This generator also fixes the count-reconciliation bug (critique T3): every other module's magnitudes derive from `N` via fixed ratios** — mailboxes ≈ N, assets ≈ 1.3N, VoIP extensions ≈ N, cardholders ≈ N + contractors, MDM enrolled ≈ assets, audit rows ≈ N × daily × retention. A 214-person company never shows 3,914 assets + 50,000 cardholders.

**Directory (`/admin/hr/employees`, paginated `/pN`)** — list columns `ID|Name|Title|Dept|Location|Manager|Status|Start`. Location ties to `Fake\Building` (`HQ — Floor 3`). Profile sub-tabs (each a distinct render): **overview** (masked personal data), **compensation** (band, base, history that sums, masked bank `••••6614`, masked tax id `***-**-4821`), **documents** (`employment_contract...pdf.zip`, `passport_scan.zip`, `background_check.zip` — decoy), **emergency** (contact + "medical notes: restricted — request access" → the funnel), **time-off / reviews / training / assets** (per-person slices linking back into their modules), **access** (SSO status, groups `payroll-admins`, "Payroll role: Administrator" — implies pivot target; isn't).

**Controls & inertness:** `Edit profile` → form → `/edit/saved` → green flash `Profile changes saved · ref HRC-<hash4>` over the *unchanged* profile (ref stable per path = "your last change"). `Start offboarding` → `Checklist created — appears within 15 minutes` (free time-burner). `Export CSV → employees_2026-08.csv.zip`.

**Payroll (`/admin/hr/payroll`)** — runs `run-2026-08` (20 months back, frozen). Run detail tabs: Summary / **Payslips** (N-row table, each → payslip page = N clicks × 20 runs of depth) / Exceptions (link to profiles) / GL Export (debits/credits that **balance**) / Audit. Payslip: earnings/deductions table, **YTD column = Σ prior payslips for that employee** (cross-footing survives). `Approve run` → `Type APPROVE to confirm` → `Approval recorded (1 of 2). Awaiting second approver: G. Okafor.` — **two-person rule is the statelessness alibi; the second approver never shows.**

**Other HR sections** — Time-Off (requests queue, calendar, balances that reconcile to ledgers), Performance (bell-curve ratings, seeded review prose from templates, "Calibration notes 🔒 Restricted" that are *visible* — the attacker believes they're already escalated), Recruiting/ATS (requisitions, pipeline, candidate + offer "approval pending 2 of 3"), Benefits (the **access-request funnel** hub: all truly-juicy items → `AR-<hash4> submitted. SLA: 2 business days.`), HR Cases (disciplinary; whistleblower "Reporter: [anonymised]" that exists nowhere by construction), Training (crosslinks: fire-warden cert → fire module; payroll-admin roster → target list).

---

### C.6 Finance portal — the greed lure

**Master generators: `Fake\Finance`** (fiscal identity, chart-of-accounts, invoice/PO/expense corpora — all reconciling), **`Fake\Vendors`**, **`Fake\Bank`**, **`Fake\Payroll`** (shares roster with `Fake\Org`).

**Coherence (the finance analog — arithmetic must close):** dashboard `Cash on hand` = Σ bank balances; `AP outstanding` = Σ open AP; aging buckets sum to total; invoice line subtotal + tax − discount = header; `paid ≤ total`; PO ↔ invoice ↔ payment ↔ bank-transaction same amount + monotonic dates; bank `closing = opening + Σcredits − Σdebits` (running-balance column recomputes down the page); vendor `YTD spend` = Σ paid invoices; balance sheet `assets = liabilities + equity`.

**AP (`/admin/finance/ap`)** — invoice list (`INV-2026-004821`, vendor, PO, dates, amount, balance, status, approver). Detail: header kv, **line-items table** (recompute to header), **remit-to panel** (fabricated masked bank — the AP jackpot the attacker screenshots), attachments (`.pdf.zip`). Controls: `Approve/Reject` → canned; `Pay now` → the **four-eyes goose-chase** (`Payment requires secondary authorization → CFO`; approving it in Approvals → `You cannot approve a payment you initiated (segregation of duties)`); `Edit remit-to` → `Change request submitted for dual approval` (BEC bait, never completes).

**Bank Accounts (`/admin/finance/banks`)** — 2–5 accounts summing to dashboard cash; Reserve holds the fat "drainable" balance. Transaction ledger `Showing 1–50 of 8,412`, each reference links to its source doc, math closes. **Inert wire-out form** on a $1M+ account (the single biggest greed lure) → `Wire WIRE-2026-3391 submitted. Awaiting dual authorization and OFAC screening.` — deterministic id `hash(seed+amount+beneficiary)`, no funds, no real system touched (stays on the honeypot side of the never-execute-a-transfer rule). Raw statement export via `preScrollHtml` + `statement_operating_2026-08.csv.zip`.

**Other:** AR (customer invoices, `Send reminder` emits **nothing** — critique S3), Expenses (reports, receipts `.pdf.zip`, policy-flag bait), PO (three-way-match illusion), Vendors (masked remit-to identical everywhere per vendor; `Edit banking` → 2-approver wall), Corporate Cards (masked last-4 only, `Reveal` → per-card inert dummy, never a PAN), Payroll Runs (register + `nacha_PR-2026-08.ach.zip` decoy), Budgets, Statements (`board_deck_Q2_2026.pdf.zip`, `audit_workpapers_2025.zip` — headline hooks), Tax, Approvals (workflow hub; steps advance in return-page text only, never persisted), Audit Log (`of 214,880`; a budgeted `vendor.bank_changed` by an unusual actor reads as in-progress fraud).

---

### C.7 IT & Platform — lateral-movement intel

**Master generators (share `Fake\Org` roster + one IP/VLAN/MAC fabric):** `Fake\Helpdesk`, `Fake\Cmdb`, `Fake\Network`, `Fake\Vpn`, `Fake\Voip`, `Fake\Printers`, `Fake\Licenses`, `Fake\Mdm`, `Fake\Mail`, `Fake\Certs`.

One IP fabric everywhere: service hosts `10.0.5.x` (syslog .30, ntp .10, tacacs .11, smtp-relay .25, radius .12, dns .1/.2); VLANs `10 Servers, 20 Employees, 30 Voice, 40 Guest, 50 Mgmt, 60 CCTV, 70 BMS/OT, 99 Quarantine`; VPN pools `10.20.x.x`. A public attacker IP that fails VPN auth appears identically (same country/ASN) in auth.log/fail2ban/mailbox sign-in — counts reconcile (`failed_auth ≥ banned`).

- **Helpdesk (`/admin/it/helpdesk`)** — ticket list `of 18,442`; threaded detail with internal notes carrying credential-shaped bait (`reset her pw to Welcome2026!`) that the never-authenticating login dead-ends; attachments `.ovpn.zip/.pcap.zip`.
- **Assets/CMDB** — `LT-00847` dense field wall (serial, MAC, hostname, last-IP, BitLocker, patch-gap bait, switch-port `sw-acc-3f-02 Gi1/0/14` that exists in Network). `Download inventory → assets-export.csv.zip`.
- **Network** — device list + per-device **running-config `<pre>`** (generic vendor-neutral CLI, masked SNMP community, syslog/NTP/TACACS IPs), port table with LLDP neighbors = literal cabling map, VLAN table, MAC/ARP tables cross-ref assets. `Download all configs → configs-backup.tar.gz`. `Ping/Traceroute` form → canned output (executes nothing).
- **VPN / VoIP / Printers / Licenses / MDM / Email / Certs** — as detailed in the brainstorm: `.ovpn.zip` profiles + `svc-backup` MFA-off; voicemail transcripts ("call the bank re: the wire") with no audio; printer scan-to-email stored creds; masked license keys (`Reveal` → per-key dummy); **MDM fleet-wide "Run script / Push app → select all"** (highest perceived RCE payoff, canned); email **suspicious external forwarding rule** (budgeted) + `Add forwarding`/`Grant Full Access` (persistence toolkit, inert; `Search & purge` never deletes — invariant on destructive actions); certs `Download private key`/`Export PFX` → **inert filler, never a valid keypair** (`.pem.zip/.pfx.zip`).

---

### C.8 Energy & Power (SCADA-flavoured)

**Generator: `Fake\Energy`** (shares `Fake\Building` topology). `/admin/energy` overview (building load kW, kWh today, peak demand, PV output, BESS SoC, PF, active alarms), SVG single-line diagram (Utility → MSB → sub-boards → PV/BESS/Genset, nodes link). Sub-meters (`MTR-3F-08`, per-meter readings/trend/config/comms; 2–3 planted `Comms FAIL` within budget → the dead-sub-meter chase). Breaker schedule with `[Toggle]` → `Breaker DB-3F-A/14 OPEN queued to FC-3F (10.20.31.44) · awaiting second operator.` UPS fleet (battery strings, SNMP tab with a **second trap-receiver IP `10.20.99.7` that appears nowhere else** — the "hidden VLAN" itch). Generator (`Start + transfer load → requires PIN at local HMI` — a PIN-entry page that does not exist). Solar (per-string, one planted `S7 fault` → electrician ticket chain). Battery/BESS. Water/gas/waste (`Emergency gas shut-off → break-glass at riser B1`). Demand-response (`Simulate DR event` → canned report). Bills archive (`elec-2026-07.pdf.zip`; one `+38% variance` dispute thread). Trends catalog (60+ `.csv.gz`... → suffix `.csv.zip`). Alarms console `of 1,284` (generic plant-speak, never scanner strings).

---

### C.9 Appliances, AV, Elevators, Robots, Rooms — the "it does everything" whimsy

The operator's named examples live here. All inert receipts.

- **Appliances (`/admin/appliances`)** — coffee machines (`water_heater.coffee_machine_orion`: brew-boiler temp 85–96 °C slider, bean %, descale, cups-today), vending (planogram slot grid, cashless/payment sub-tab with masked `**** 4242`), kitchen (fridge/dishwasher/ice/Zip-tap), signage (`media_player`: push content, **Emergency message** text box → escaped canned "displayed on 11 screens"), PA/audio (zones, **Send page** TTS box → canned, emits nothing).
- **Elevators (`/admin/elevators`)** — per-car state/floor/load/mode; floor-call matrix, `Recall to lobby`, `Independent service`, `Run test cycle`, `Take out of service` → canned; **music sub-tab** (`media_player.elevator_music`: now-playing, playlist reorder, source select, `Upload MP3 → playlist_lobby.m3u.zip` decoy). Faults, trips, maintenance (fake vendor contact).
- **Robots (`/admin/robots`)** — `vacuum`/`lawn_mower`: state, battery, fan-speed, room-select clean map (SVG), consumables. Start/dock → canned.
- **Meeting Rooms (`/admin/rooms`)** — room + `calendar` bookings (titles leak intel: `Board Review`, `M&A — Project Falcon`, `Layoffs planning`, `Interview: <name>`), occupancy, AV bundle (aggregates ~6 other-domain entities per room). Book/Cancel/Extend → canned.
- **Automations & Scenes (`/admin/automations`)** — `automation`/`script`/`scene` list; per-automation **Traces** sub-tab (execution timeline — a sub-rabbit-hole each); `scene.night_secure`/`script.lockdown`/`script.evacuate_building` = irresistible inert buttons; scene member lists cross-link into every domain.

---

## D. UI/UX, layout, widgets, and how controls stay inert

### D.1 Layout regions

```
┌─ alte-navbar (top, fixed): brand · OneControl  [ global search ▸ ]  🔔3  AM ▾ ─┐
├──────────┬──────────────────────────────────────────────────────────────────┤
│ sidebar  │ page-header:  Module ›  breadcrumbs                                │
│ (grouped │               H1 title                    [ action buttons ]       │
│  fixed   │ ── stat-tile row (statCardsHtml) ───────────────────────────────  │
│  scroll) │ ── widget grid (auto-fit cards: gauges, sparklines, tables) ────   │
│          │ ── sub-tab strip (Overview|History|Schedule|Settings|Logs|…) ──    │
└──────────┴──────────────────────────────────────────────────────────────────┘
```

### D.2 CSS direction (append to `css()`, single-string concat style, extend the `alte-` language)

- Status custom properties on `:root`: `--ok:#2e8b57 --warn:#c07a1a --crit:#b23b3b --idle:#9aa1a8 --info:#3b7ea1`. Every widget themes off these.
- New classes: `.alte-nav-group-title` (uppercase, letter-spaced), `.alte-page-head` (flex space-between), `.alte-breadcrumb`, `.alte-tabs`/`.alte-tab.is-active`, `.alte-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}`, `.alte-pill.is-ok/.is-warn/.is-crit/.is-idle`, `.alte-toggle` (track+knob via `::before`), `.alte-slider`+`.alte-slider-fill`, `.alte-btn`/`.alte-btn-danger`, top-bar `.alte-search`/`.alte-bell-badge`/`.alte-userchip` (name from roster, seeded).
- Self-contained: no external CSS/JS/fonts/images (CSP-clean, anti-fingerprint). Wide tables/logs keep `overflow-x:auto`. Responsive via `minmax` collapse.

### D.3 Widget vocabulary (add to `AbstractSkin`, all SVG/CSS, escape-by-construction, seeded)

| Widget | Helper | Notes |
|---|---|---|
| Status pill | `pillHtml($text,$state)` | build first |
| Radial gauge | `gaugeHtml($value,$min,$max,$unit,$band)` | inline SVG arc; band colour by threshold |
| Sparkline | `sparklineHtml(array $points,$class)` | SVG `<polyline>`; points `hash(seed+entity+field+i)` |
| Bar chart | `barsHtml(array $vals)` | CSS flex bars |
| Donut | `donutHtml(array $slices)` | SVG stroke-dasharray, slices sum 100 |
| Toggle | `toggleHtml($on,$href)` | switch-styled **`<a>`** → control leaf |
| Slider | `sliderHtml($value,$min,$max,$stepHrefFn)` | filled track + `−`/`+` links to `.../set/{n}` |
| Calendar/week grid | `calendarHtml(array $events)` | room bookings, PTO |
| Timeline | `timelineHtml(array $events)` | audit/activity, monotonic ts |
| Floorplan | `floorplanHtml($floor,$rooms,$navBase)` | SVG `<rect>`/`<polygon>` `<a>` rooms + status dots |
| Org tree | `orgTreeHtml(array $nodes)` | nested `<ul>` CSS tree |
| Camera tile | `cameraTileHtml($id,$navBase)` | SVG placeholder — **never `<img src>`** |
| Breadcrumbs | `breadcrumbHtml(array $path,$navBase)` | each crumb links its own prefix |
| Control receipt | `controlResultCard($navBase,$action,$arg,$seed)` | **the one inert-control renderer** |

### D.4 Deterministic depth (the endless-but-coherent surface)

Row `i` on page `N` = `hash(seed+section+filter+i)`; `total` = a big seeded constant; page 400 of 1,928 renders instantly and identically. **Unknown/fuzzed entity slug still renders a plausible detail** keyed by the slug (`state = f(hash(seed+slug))`) — a crawler never falls off the edge; a 404 inside the panel is a tell.

### D.5 How controls stay inert (JS decision: **no JS**)

**Pattern A — link-to-confirmation (default, zero JS).** Every toggle/slider-step/mode-pill/button is `<a href>` to a control leaf `.../<action>/<arg>` → `controlResultCard()`:

> **Command queued** — `Setpoint → 23 °C` on `Zone 3F Northwest`. Queued to controller `bacnet://10.0.50.14`; applies at next poll (~30 s), write-priority 8. *Job `cmd-8f3a21`* (= `hash(seed+path)`).

The `arg` is echoed **escaped** (the only place attacker input appears). The device detail still shows its **seeded** state — "applies at next poll" makes the non-change read as latency, not a fake. **Per-module phrasing vocab (T4)**; per-module soft-deny/interlock/dual-auth wording for scary verbs (D burns more time than success).

**Pattern B — form POST → same confirmation** (numeric/free inputs: setpoint field, book-a-room, send-command box). App returns the Pattern-A card echoing submitted values (escaped). Status **always app-chosen 200**, `Content-Type: text/html`; never a model-chosen 3xx (no open-redirect); never a 500 on malformed input (degrade to the plain card or plain 404). No state written; re-POST = same page.

**Pattern C — inline JS cosmetic toggle: rejected.** It breaks no-JS purity, a toggle that flips then resets on reload is *itself a tell*, and JS enlarges the fingerprint/CSP surface the project deliberately minimizes. The "queued, applies at next poll" copy already buys the interactivity feel with zero script.

### D.6 Global search + breadcrumbs

Breadcrumbs = pure function of the path (re-join slugified prefixes; last crumb plain text; slug→title map per module). Global search `<form method="get" action="/admin/search">` (or `/admin/search/{q}`): slugify + **escape** the query, echo `Results for "payroll"`, return a **canned deterministic result set** (`hash(seed+querySlug+i)` → mixed employees/invoices/devices/rooms, each a deep link). Always returns plausible hits (search "password"/"wire"/"root"/"ssn" → confident rows). Never reflect raw query; never treat as routing.

---

## E. Realism rules + tells to avoid

- **E1 (T1) — Dashboard shows business metrics, never secrets.** Replace `lootCard()`'s `password_hash` table (`AdminLteSkin.php:223`, composed @179) with tiles + a benign "recent activity" table (name/role/last-login). Hashes/2FA-secrets move **one drill-down deep** to `/admin/users/<id>/security` or the phpMyAdmin Browse view (which owns that convention correctly).
- **E2 (T2) — Anomaly budget.** `hash(seed+module)` plants 0–2 anomalies per module; the rest render clean. Never the fifty-honeytoken buffet.
- **E3 (T3) — Counts reconcile from one `N`.** All magnitudes via the `Fake\Org` ratio table. No 214-person company with 50,000 badges.
- **E4 (T4) — Vary pending/interlock copy per module.** No universal template string a crawler can diff.
- **E5 (T5) — Per-secret reveal dummies** in the right shape; never one global `EXAMPLE0000`.
- **E6 (T6) — Escape everything reflected.** Search, PA broadcast, signage message, room title, add-note, receipt `arg` → `esc()`, slugify where it is a path/href, never persist. **PIN/access codes are never reflected at all.**
- **E7 (T7) — Resemblance, not trademark.** Invented model/build names primary (`PowerVault PR-4000`, `helios-bms`, `OmniLift MRL-8`). If a real brand name appears as data, pair it with an invented model/build. Never reproduce a real product's markup/CSS/logo.
- **E8 (S1) — Every download ends `.zip`/`.tar.gz`** (only extensions `serveDecoyArchive` serves). A bare `.pdf` under `/admin/*` renders HTML = Content-Type mismatch tell.
- **E9 (S3/S4) — No real side effects.** "Send/e-file/transmit/reminder" emit nothing; fabricated log IPs never reach `maybeReport`/AbuseIPDB; geo/ASN are fabricated constants, never a live WHOIS.
- **E10 (S5/S6) — Inert by construction.** Camera frames inline SVG only; RTSP/OCPP strings open no socket; cert keys are non-functional filler; life-safety verbs return guarded denials or pending, never "done"; any fault → plain 404, never 500.
- **E11 (F4/F6) — Determinism + no signatures.** No `time()/rand()/shuffle()` in generators; ages from one `deployEpoch`; invented ids only; never nuclei matcher words or CRS rule ids/`msg`.
- **E12 (F1) — Version discipline.** Generators live app-side (PHP 8.0 OK). If a fact must reach a core template, put that piece in core and keep it 7.3-clean (no enums, named args, `str_contains`, constructor promotion).

---

## F. Build mapping + phased plan

### F.1 New code artifacts

- **Router/helpers:** `Funnypot\App\Render\PanelRoute` (positional parse + `pN`); extend `AbstractSkin` with the D.3 widget helpers (`pillHtml`, `gaugeHtml`, `sparklineHtml`, `breadcrumbHtml`, `controlResultCard` first; then `toggleHtml`/`sliderHtml`/`calendarHtml`/`floorplanHtml`/`cameraTileHtml`/`orgTreeHtml`/`barsHtml`/`donutHtml`/`timelineHtml`).
- **Skin:** extend the existing `AdminLteSkin` — swap `viewFor()`→`PanelRoute::parse()`, add module `sectionFor` cases, fix the `:223` dashboard tell. Keep it registered last.
- **Master generators (build in this order):** `Fake\Building`, `Fake\Org`, then `Fake\Finance`+`Fake\Vendors`+`Fake\Bank`+`Fake\Payroll`, `Fake\Safety`+`Fake\Cctv`+`Fake\Sensors`, `Fake\Energy`, and the IT family (`Fake\Helpdesk/Cmdb/Network/Vpn/Voip/Printers/Licenses/Mdm/Mail/Certs`). All `fromSeed(int $seed)`, pure `hash(seed+slot)`.
- **Decoy handler:** confirm `serveDecoyArchive` fires for the `.zip`-suffixed download paths and that the engine returns null for them; keep the `.zip`/`.tar.gz`-everywhere convention rather than extending the extension map.

### F.2 Two blockers to clear before writing any module

1. **(F2/F3)** Land `PanelRoute` + the single-skin/master-generator decision. No depth works while `viewFor()` reads only the last segment.
2. **(S1)** Settle the download strategy — suffix every download `.zip`/`.tar.gz`.

### F.3 Top-20 build-first (highest depth/time-burn per effort, lowest risk)

1. `PanelRoute::parse` + `breadcrumbHtml` — the depth enabler.
2. `Fake\Building` master (site→floors→zones→rooms→devices→controllers).
3. `Fake\Org` master (roster `N`, ids, manager tree, one IP/badge/ext mapping + count-ratio table).
4. `controlResultCard()` shared inert-confirmation helper (per-module pending vocab, escaped arg).
5. Log-scroll pages (reuse `preScrollHtml`): access-events, incidents, finance audit, VPN/auth, CDR — huge scroll, zero new widgets.
6. **Access Control** — door + cardholder/badge lists, per-door detail, unlock leaf with server-room soft-deny.
7. **Fire & Life-Safety** — suppression table + two-step guarded disable (fake unvalidated/unreflected PIN) → interlock denial.
8. **CCTV** — inline-SVG camera grid + detail + RTSP/NVR bait + `.zip` recordings.
9. **HVAC + BACnet points** — zone list + setpoint leaf + CRAC↔server-room cross-link (needs `gaugeHtml`).
10. **Employee directory + profile tabs** — masked PII, paginated enumeration surface.
11. **Payroll runs + payslip** with reconciling sums.
12. **Finance AP** — invoice list + detail (lines reconcile) + Approvals four-eyes dead-end.
13. **Bank accounts + transaction ledger** (running balance reconciles) + inert wire form → dual-auth/OFAC wall.
14. **Vendors + masked remit-to** + edit-banking → 2-approver wall (BEC bait).
15. **Device/integrations registry** (MQTT/BACnet/SNMP/Modbus host:port bait), paginated — densest per-byte pivot lure.
16. **Sensor/environment long tail** (HA device-class fleets) — hundreds of read-only rows + `gaugeHtml`, cheapest breadth.
17. **Building floorplan SVG hub** (`floorplanHtml`) — spatial index into all building modules.
18. **Meeting-room booking calendars** (`calendarHtml`) — org-intel leak.
19. **Lighting + covers** — toggle/slider leaves; broad candy.
20. **Appliances/AV** — elevator music, coffee temp, PA/signage boxes (escaped reflect) — the operator's named examples.

### F.4 Phasing

- **Phase 0 (enablers):** items 1–5 + widget helpers `pillHtml/gaugeHtml/sparklineHtml`. Fix the `:223` dashboard tell. Nothing user-visible ships without these.
- **Phase 1 (flagship lures):** items 6–9 (access, fire, CCTV, HVAC) — the strongest physical-power fantasies + biggest log scrolls.
- **Phase 2 (greed + PII):** items 10–14 (HR directory/payroll, finance AP/bank/vendors) — arithmetic-closing loot.
- **Phase 3 (breadth):** items 15–20 (IT registry, sensor long tail, floorplan hub, rooms, lighting/covers, appliances) + remaining HA domains, energy/BMS, elevators/robots/automations.
- **Phase 4 (polish):** global search, activity feed, anomaly-budget tuning, per-module pending-copy vocab, cross-module link audit (verify one roster/topology/IP fabric holds end-to-end).

### F.5 Ten believability details to bake in (from the critique)

1. "Queued — applies at next poll (~60 s), write-priority 8" (varied per module).
2. Guarded soft-denials on the scariest verbs (dual-auth / hardware interlock / OFAC / awaiting-second-approver).
3. Arithmetic that closes (invoice→total, YTD=Σ, bank closing, aging buckets, assets=liab+equity).
4. One topology / one roster / one IP fabric across modules.
5. Frozen "now" framed "cached 30 s / last poll 42 s ago" from `deployEpoch`, monotonic per page.
6. Budgeted, linked anomalies — one dirty filter / one comms-fail meter → a WO/incident that ends one step short.
7. Reluctant secrets — masked at rest, per-key non-validating reveal, invalid-format SSN/IBAN/last-4.
8. Ops-grade deep sub-tabs (automation Traces, BACnet points, SLC loop map, PDU outlet grid, access-level matrix, running-config `<pre>`).
9. Enterprise friction as the trap (two-person rule, "verification callback scheduled", "SLA 2 business days", "propagates in ~2 min").
10. "Update available (security fixes)" + signed-image-required upload refusal — looks patched/hardened, invites CVE-hunting that yields nothing.

**Files to touch:** `funnypot/src/App/Render/Skins/AdminLteSkin.php` (viewFor→PanelRoute, module sectionFor cases, fix `:223`), `funnypot/src/App/Render/AbstractSkin.php` (widget helpers), new `funnypot/src/App/Render/PanelRoute.php`, new `funnypot/src/App/Render/Fake/Fake{Building,Org,Finance,Vendors,Bank,Payroll,Safety,Cctv,Sensors,Energy,Helpdesk,Cmdb,Network,Vpn,Voip,Printers,Licenses,Mdm,Mail,Certs}.php`; verify `funnypot/src/App/Http/HoneypotController.php::serveDecoyArchive` (@259) against the `.zip`-everywhere download convention.