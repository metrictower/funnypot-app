Grounded in the actual code (`AdminLteSkin.php`, `AbstractSkin`, `HoneypotController::serveDecoyArchive`, both composer.json files). Adversarial review follows.

---

# Adversarial review — deep office/enterprise honeypot dashboard

## 1. TELLS / over-the-top (and fixes)

**T1 — `password_hash` on the dashboard (confirmed real, `AdminLteSkin.php:223` `lootCard`).** No real admin landing page renders a `password_hash` column. It's the loudest tell in the current code and the designs inherit it. **Fix:** dashboard shows business metrics + a benign "recent activity" table (name/role/last-login, no secrets). Move hashes to `/users/<id>/security` sub-tab or the phpMyAdmin Browse view — one drill-down deep, never the landing.

**T2 — the Christmas-tree-of-honeytokens problem (the biggest design-wide tell).** Every module plants its juiciest anomaly *simultaneously*: MASTER badge `00001`, lost-but-active badges, ALL-DOORS contractor, `svc-backup` MFA-off, 03:00 GRANTED to server room, suspicious external mail-forward already installed, camera "footage gap", bypassed window sensor, RF-jam trouble, +38% bill variance, whistleblower case, `Do-not-hire` note. Each *alone* is a plausible finding; **all present in one seed reads as staged.** Real orgs have one or two anomalies, not fifty. **Fix:** a per-deploy **anomaly budget** — `hash(seed)` selects 1–2 planted anomalies per module (often zero), the rest render clean. Slow-burn: the attacker who finds *one* juicy thing trusts the site more than one who finds a buffet.

**T3 — counts don't reconcile across modules (violates the coherence invariant the designs themselves demand).** Example numbers: headcount 214, but 3,914 assets + 4,000 AV/endpoint seats + 1,204 mailboxes + 50,000 cardholders + 512 extensions. A 214-person company cannot have those. Cross-module coherence is *claimed* but the sample magnitudes contradict. **Fix:** derive every count from one seeded `headcount N` via fixed ratios (mailboxes≈N, assets≈1.3N, extensions≈N, cardholders≈N+contractors, audit rows≈N×daily×retention). Bake the ratio table into the master `Fake\Org`/`Fake\Building` generators.

**T4 — uniform "pending" copy is a fingerprint.** If every control in every module returns the identical string ("applies at next controller poll (~60s)"), a crawler diffs two receipts and sees the template. **Fix:** a small per-module vocabulary of pending/interlock phrasings, indexed by `hash(seed+module)`.

**T5 — identical reveal dummy.** `EXAMPLE0000` for every "reveal" means revealing two keys shows the same value = tell. **Fix:** derive a per-secret non-validating dummy `hash(seed+keyId)` in the right shape (`sk_live_…EXAMPLE`, `•••• 0000` cards).

**T6 — reflected input in receipts/search/PA/signage/notes.** PA "broadcast", signage "push message", global search, book-a-room title, add-note, keypad PIN — all echo attacker text. Unescaped, that's reflected XSS *in your own operator dashboard*. **Fix (hard rule):** every echoed value goes through `esc()`, is slugified where it's a path/href, is never persisted, and the PIN/code is **never** reflected at all.

**T7 — real trademarks as data (judgment call).** Axis/Hikvision/Notifier/DSC/Genetec/NetSuite/Okta as *model vocab* is lower-risk than reproducing markup, but "resemblance-only" is cleaner with invented model names (`PowerVault PR-4000`, `helios-bms` — good examples already in the BMS section). Keep invented names primary; if a real brand appears, pair it with an invented model/build. Never reproduce a real product's markup/CSS/logo (the designs honor this).

## 2. INERT / SAFETY (and fixes)

**S1 — download extensions will break or leak (HIGHEST-priority buildability+safety gap).** `serveDecoyArchive()` only matches `.tar.gz / .tgz / .gz / .zip` and only fires when the engine returns *no* response. The designs propose hundreds of downloads ending `.pdf .csv .xlsx .mp4 .ovpn .pem .pfx .csr .pst .ach .wav .m3u .dwg .bin .cfg .lic .ofx .bak`. Those **won't be served as files** — and because `matches()` claims the whole `/admin/*` subtree, a link like `/admin/finance/board_deck.pdf` renders an **HTML admin page**, i.e. a `.pdf` served as `text/html` = Content-Type mismatch (breaks invariant #5) and an obvious tell. **Fix (choose one):** (a) simplest/proven — suffix *every* download `.zip`/`.tar.gz` (`board_deck_Q2.pdf.zip`), which already routes correctly; or (b) extend the `$map` with each extension → a real decoy asset + correct `Content-Type`, AND ensure the engine returns `null` for those paths so the decoy fallback fires. Prefer (a) everywhere.

**S2 — query-string params.** `?temp=94 ?rgb= ?floor=6 ?level= ?page=N ?site=` — the current skin ignores query entirely. Any adopted param must be slugified+escaped before echo and never used to route. Keep the design's path-based pagination (`/p7`) instead of `?page=` where possible so the cache key stays clean.

**S3 — "send"/"e-file"/"transmit NACHA"/"send reminder" must emit nothing.** Safe *only* because they're static renders. Explicit rule: do **not** wire these confirmations to any real outbound (SMTP, the app's `notify`/`tts` paths, AbuseIPDB, webhooks). Text-only receipt, no side effect.

**S4 — fake-log IPs must never reach the reporter.** All the fabricated attacker IPs in access/auth/audit/VPN logs are display strings; confirm none are passed to `maybeReport`/AbuseIPDB. Use TEST-NET (`198.51.100.0/24`, `203.0.113.0/24`) + RFC1918 only; geo/ASN shown must be fabricated constants, never a live WHOIS on a real IP.

**S5 — camera tiles / RTSP / private keys are inert by construction.** Camera "frames" must be **inline SVG** (no `<img src>` — also satisfies the no-external-assets/CSP rule); RTSP/OCPP/NVR URLs are inert strings that open no socket; cert "private key / PFX" downloads are non-functional filler (never a valid keypair) — and subject to S1's extension fix to serve at all.

**S6 — life-safety verbs.** Correctly handled by the designs: strongest verbs (disable suppression, disarm, manual release) return **guarded denials** (dual-auth / hardware key-switch interlock), milder ones return "pending." Reinforce: no life-safety verb ever returns "done/activated"; any internal fault degrades to the plain 404, never a 500 (invariant #2).

## 3. DETERMINISM / FINGERPRINT / version feasibility

**F1 — PHP version is 8.0, not 7.3 (the designs repeat "7.3" incorrectly for this tier).** Skins and `Funnypot\App\Render\Fake\*` live in the **app**, whose composer is `"php": ">=8.0"`. `funnypot-core` is `>=7.3`. So the new generators *may* use 8.0. **But** if any generator is meant to be shared into core templates it must live in core and stay 7.3-clean (no enums, no named args, no `str_contains`, no constructor promotion). Recommendation: keep these generators app-side (8.0); only push a fact into core when a template needs it.

**F2 — routing is the load-bearing enabler.** `viewFor()` uses `end($segs)` only, so `/admin/hvac/vav-03/history` → `history` → dashboard. **Nothing deep works until `PanelRoute::parse()` (positional `module/section/entity/subtab/action/arg`, trailing `pN`) exists.** Build it first. `matches()` already claims deep `/admin/*` via the `admin` segment, so paths reach the skin; keep AdminLteSkin registered **last**.

**F3 — one skin, not many.** The designs oscillate between "new FinancePortalSkin/FacilitiesSkin" and "extend AdminLteSkin." **Prefer ONE deep panel skin + per-module section renderers + shared master generators.** Separate skins fragment the single seed/roster/IP/topology fabric that every coherence invariant depends on, and add matcher-precedence bugs. Caveat: if the operator wants these reachable at root (`/finance/*`, `/iot/*`) not just under a mount, either add those tokens to `matches()` or register narrow dedicated skins that delegate to the same renderers/generators.

**F4 — determinism hygiene.** All values `hash(seed+slot)`; **no** `time()`/`date()`/`rand()`/`shuffle()`/`mt_rand` in any generator (the store's `gmdate('c')` for real logging is fine and separate). "Ages" from one frozen `deployEpoch` constant, monotonic within a page. Paginated "of 214,880" pages must compute row *i* on demand (`hash(seed+section+i)`), never build the full set.

**F5 — no JS (skip Pattern C).** The optional inline-JS cosmetic toggle enlarges the fingerprint/CSP surface, and a toggle that flips then resets on reload is itself a tell. Link-to-confirmation (Pattern A) + form-POST-to-confirmation (Pattern B) cover everything. All widgets inline SVG/CSS, self-contained, in `css()`.

**F6 — no scanner-signature strings.** Invent all controller/rule/object/point ids (`WAF-1xxxx`, `BMS-CTRL-03`, `AV:14`). Never emit nuclei matcher words or CRS rule ids/`msg` (invariant #1). None of the designs do — keep it that way in any SIEM/WAF widget.

## 4. Build FIRST — 20 highest-value / lowest-risk / most-time-wasting

Ordered; each reuses existing helpers, needs minimal new widget code, and carries the S1 download rule.

1. **`PanelRoute::parse` + breadcrumbs** — enabler; without it there is no depth.
2. **`Fake\Building` master** (site→floors→zones→rooms→devices→controllers) — coherence spine for all building modules.
3. **`Fake\Org` master** (one roster N, ids, manager tree, one IP/badge/ext mapping) — spine for HR/finance/badge/booking/audit-actor coherence.
4. **`controlResultCard()`** shared inert-confirmation helper (`CMD-<hash>`, per-module pending vocab, escaped arg) — the one mechanism every control reuses.
5. **Log-scroll pages** (reuse `preScrollHtml`): access-events, incidents, finance audit, VPN/auth, CDR — huge scroll, zero new widgets, top time-burn per byte.
6. **Access Control** — door list + cardholder/badge list + per-door detail + unlock leaf with server-room soft-deny. Strongest physical lure, all tables.
7. **Fire & Life-Safety** — suppression table + two-step guarded disable (fake PIN, escaped, never validated) → interlock denial. Flagship dead-end.
8. **CCTV** — inline-SVG camera-tile grid + detail + RTSP/NVR string bait + recordings list (`.zip`-suffixed).
9. **HVAC + BACnet points** — zone list + setpoint leaf + CRAC↔server-room cross-link. Dense recon, one gauge.
10. **Employee directory + profile tabs** (overview/comp/documents), masked PII, paginated — enumeration surface.
11. **Payroll runs + run detail + payslip** with reconciling sums — greed + cross-footing trust.
12. **Finance AP** — invoice list + detail (lines reconcile) + Approvals four-eyes dead-end.
13. **Bank accounts + transaction ledger** (running balance reconciles, refs cross-link) + inert wire form → dual-auth/OFAC wall.
14. **Vendors + masked remit-to** + edit-banking → 2-approver wall (BEC bait).
15. **Device/integrations registry** (MQTT/BACnet/SNMP/Modbus host:port bait), paginated — densest per-byte pivot lure.
16. **Sensor/environment long tail** (HA device-class fleets) — hundreds of read-only rows + gauge; cheapest breadth, Netdata-style scroll.
17. **Building floorplan SVG hub** (`floorplanHtml`) — spatial index; every room → all building modules.
18. **Meeting-room booking calendars** — org-intel leak (titles/attendees), one calendar widget.
19. **Lighting + covers** — toggle/slider leaves; broad candy.
20. **Appliances/AV** — elevator-music, coffee-temp, PA/signage boxes (escaped reflect) — the operator's named examples + "it does everything" whimsy.

*Widgets to build once, in this order (cover ~80%):* `pillHtml`, `gaugeHtml` (SVG), `sparklineHtml` (SVG), `breadcrumbHtml`, `controlResultCard`; then `toggleHtml`/`sliderHtml` (as `<a>`), `calendarHtml`, `floorplanHtml`, `cameraTileHtml`, `orgTreeHtml`.

## 4b. 10 best believability details

1. **"Queued — applies at next controller poll (~60 s), write-priority 8"** — makes a stateless control read as eventually-consistent; the unchanged state on reload looks like latency, not a fake. (Vary copy per module — see T4.)
2. **Guarded soft-denials on the scariest verbs** (dual-auth / hardware key-switch interlock / Level-3 / OFAC / "awaiting second approver") — failure burns *more* time than success and is permanently dead-ended.
3. **Arithmetic that actually closes** — invoice lines→total, YTD=Σ payslips, bank closing=opening+credits−debits, aging buckets sum, assets=liabilities+equity — defeats the doubter's cross-foot.
4. **One topology / one roster / one IP fabric** — the same person is booking organizer + badge holder + desk owner + payslip + audit actor; the same `10.0.50.x` controller appears in HVAC points, camera streams, ACS, and the fire panel.
5. **Frozen "now" framed as "cached 30 s / last poll 42 s ago"** from one `deployEpoch`, monotonic within a page — a static reload isn't a tell.
6. **Budgeted, linked anomalies** (see T2): one dirty filter / one string fault / one comms-fail meter, each linking to a work-order or incident that ends one step short — not everything broken at once.
7. **Reluctant secrets** — masked at rest, per-key non-validating reveal dummy, last-4 cards, invalid-format SSN/NI/IBAN — reads hardened, not baited.
8. **Ops-grade deep sub-tabs fakes usually omit** — automation Traces, BACnet points list, SLC loop address map, PDU outlet grid, access-level matrix, running-config `<pre>` — density that says "real product."
9. **Enterprise friction as the trap** — two-person rule, "verification callback scheduled," "SLA 2 business days," "propagates to readers in ~2 min" — the attacker's patience is the sink.
10. **Firmware "update available (security fixes)" + signed-image-required upload refusal** — looks patched/hardened, invites CVE-hunting that yields nothing.

**Two things to fix before writing any module:** (S1) settle the download-extension strategy — suffix everything `.zip`/`.tar.gz`; and (F2/F3) land `PanelRoute` + the single-skin/master-generator decision. Everything else composes cleanly on top of the existing `AbstractSkin` helpers.