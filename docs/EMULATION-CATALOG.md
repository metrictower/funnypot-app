# Emulation catalog: the configurable "which vulns do we serve" surface

funnypot can emulate a lot: attack classes, product decoys, protocol services, and the whole
nuclei-reflection corpus. The emulation catalog makes that a single, operator-controlled toggle
list. It auto-registers new capabilities, so the list never drifts out of sync with what the engine
actually ships.

## The idea: derived catalog + sparse overlay

- **Catalog = derived, never hand-maintained.** `funnypot compile-catalog` scans the templates
  (`templates/attack`, `templates/route`, `templates/protocol`) plus the compiled nuclei corpus and
  emits `resources/compiled/funnypot-catalog.php`, one entry per capability
  (`id, kind, title, category, cve, severity, ports, default, source`). Add a template + recompile
  and it appears automatically. Templates may declare `title`/`category`/`cve`/`default`; anything
  omitted is derived (title humanized from the id, category from tags, cve from a `cve-…` tag,
  default = on).
- **Config = a sparse JSON overlay.** `funnypot-vulns.json` lists on/off choices. Only differences
  from the catalog default need to be present, so a brand-new capability takes its declared default
  without touching the file. The JSON is the canonical control surface; a dashboard is just a UI
  that reads and writes it.

```json
{
  "version": 1,
  "vulns": { "attack-cmdi-unix": false, "service-telnet": false, "nuclei-reflection": true }
}
```

Resolution order is override, then catalog default, then on.

## What the catalog does not cover: app-native surfaces

The catalog lists what the core engine serves from templates. funnypot-app also has its own surfaces
that answer some paths with app code (the labyrinth and context-polluters, the attrition journey, the
token-mint account surface and its SSRF proof-bait, the fake AI-API chat, the Docker API). They are not catalog entries and
`funnypot-vulns.json` does not switch them: each has its own environment flag, off by default, and
most also need the tarpit master switch (`FUNNYPOT_TARPIT`). See `demo/README.md` for the flags.

They meet the engine in two different places:
- **Router-level surfaces** (the labyrinth, the polluters, the attrition journey, the AI-API chat, the
  Docker API) answer their paths before the honeypot runs. The engine never sees that traffic, so a
  catalog switch has no effect there, and each surface does its own logging (and, where it has one, its
  own reporting).
- **Serve-seam surfaces** (the token-mint account surface, its SSRF proof-bait — `/settings/webhooks…`,
  `/settings/imports…`, `/settings/storage…`, `/api/v2/user/{hooks,imports,storage}…` and the `/v2/` twins —
  and the web-shell console once merged) answer
  inside `HoneypotController` after the engine has run. Detection, the hit row and the AbuseIPDB / Threat
  Intel reports are the engine's, exactly as on any other path, so a catalog entry switched off stops
  being detected and reported there too; only the response body is the surface's.

## Auto-add mechanics

`funnypot vulns:sync` (host, needs the compiled catalog) materializes the full list, and so does its
vendor-free demo twin `demo/vulns-sync.php`, run on container boot. Existing choices are preserved,
new catalog ids are added at their default, and ids no longer in the catalog are dropped. So the
flow is:

1. add a template, then `compile-catalog` (CI does this after every template recompile);
2. deploy, then `vulns-sync` refreshes `funnypot-vulns.json` and the new capability shows up enabled;
3. operator flips it off in the JSON (or the dashboard) if they don't want it.

## Enforcement

`EmulationPolicy::disabledIds()` is fed into the engine as a deny-set:

| kind | how it's gated | granularity |
|---|---|---|
| `attack` | `TemplateAttackEmulator::disable()` skips the rule id | per-vuln ✅ |
| `service` | `demo/listen.php` refuses to bind a disabled service (restart to apply) | per-service ✅ |
| `corpus` | `nuclei-reflection` off means `Honeypot` drops nuclei-derived bundles | one group toggle ✅ |
| `route` | folded via the exclude machinery | new_page decoys ✅; enrich decoys are display-only in v1 |

The policy is an extra filter on top of the existing mode/gate/severity-ceiling. It decides which
capabilities are live, not whether respond mode is on.

### Known v1 limitation

Enrich-style route decoys (e.g. `.git/config`) augment an existing nuclei bundle rather than owning
their own, so toggling them individually is a partial no-op. They follow the `nuclei-reflection`
group instead. new_page decoys (their own `route-*` bundle) toggle cleanly. Per-decoy enforcement
for enrich routes is future work.

## CLI

```bash
funnypot compile-catalog                 # re-derive the catalog from templates
funnypot vulns:sync --out=funnypot-vulns.json   # materialize the toggle list (auto-add new)
funnypot vulns:list                      # print every capability + its on/off state
```
