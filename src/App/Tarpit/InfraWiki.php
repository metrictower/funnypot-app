<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\Core\Support\PersonaIdentity;
use Throwable;

/**
 * FP-0808 — the seeded procedural infra-wiki model. A deterministic, per-deploy generator that turns the
 * {@see \Funnypot\App\Tarpit\InfraCatalog} archetypes into a sprawling fake infrastructure inventory: a
 * fleet of services across the 13 lifecycle categories, each with a per-deploy host / port / version /
 * owner / lifecycle status and a cyclic dependency web (depends_on / backed_up_to / monitored_by). The
 * {@see InfraWikiRenderer} turns this model into the served Markdown.
 *
 * The point (spec §Why): this is false RECON DATA, not a directive — an AI pentester consumes it as
 * legitimate facts and acts on it (enumerate the fake services, chase the migration trails, attempt the
 * documented auth), so the injection boundary never fires. The waste is the agent's own task-driven work.
 *
 * Invariants (shared with the labyrinth/polluter tarpits):
 *  - DETERMINISTIC per deploy: identical $personaSeed ⇒ byte-identical model forever (re-fetches never
 *    contradict, so the agent can't catch a flip); a different deploy ⇒ different company/hosts/versions/
 *    owners/statuses/edges/constants (no fleet constant ⇒ not fingerprintable).
 *  - FINGERPRINT-SAFE: every GENERATED token (slug, host octet, derivation constant) is routed through the
 *    systemic {@see InertSecret} clean-gate so no digit run can spell a detector signature. Tool/version
 *    names are generic product facts from the catalog (vetted, dot-separated — never a bare 6-digit run).
 *  - COHERENT: company name/slug/domain come from the SAME {@see PersonaIdentity} every other fake surface
 *    uses, so the infra doc names the same company as the config dump, the labyrinth and the panels.
 *  - BOUNDED: the service set is a fixed function of the seed (the catalog size), so the model is O(catalog)
 *    to build; the renderer caps bytes on top.
 *
 * Seed derivation is app-local (`hash('sha256', $personaSeed.'|infra|'.$label)`), the exact idiom
 * {@see SeededStream}/{@see ConfigDump} use — NO core `SubSeed` namespace is added (that would be a core
 * change), keeping this purely app-tier.
 */
final class InfraWiki
{
    /** The on-demand sub-doc path prefixes the doc-labyrinth references (served by InfraDocController). */
    public const RUNBOOK_PREFIX = '/docs/runbooks/';
    public const MIGRATION_PREFIX = '/docs/migrations/';
    public const BACKUP_CATALOG_PATH = '/ops/backup-catalog.md';

    /** The lifecycle statuses a service can land in (spec §"Content taxonomy"). */
    private const STATUSES = ['prod', 'staging', 'legacy', 'deprecated', 'migrating', 'archived'];

    /** Generic owning-team names (seed-picked; inert org facts, never real people). */
    private const TEAMS = [
        'platform', 'sre', 'infra', 'data-eng', 'security', 'payments', 'identity', 'web', 'mobile',
        'analytics', 'devex', 'networking', 'billing', 'search', 'messaging',
    ];

    /**
     * Vetted pools of plausible-looking large constants for the compute-bait appendix. Seed-picked so the
     * constants vary per deploy, and NUMERIC (never routed through InertSecret::derive, whose letter
     * fallback would make them non-numeric — the plan-review nit). Every entry is dot-free and carries no
     * bare 6-digit `9…` run, so it is fingerprint-clean on its own; the full-prose fingerprint sweep is
     * the backstop.
     */
    private const PRIME_INDEX_POOL = [1000003, 1299709, 1500007, 2000003, 1048573, 1234577, 1685537, 1360897];
    private const ITERATION_POOL = [1048576, 2097152, 4194304, 1000000, 1500000, 2500000, 3200000, 1600000];
    private const FIB_INDEX_POOL = [10000019, 12500000, 15000017, 20000003, 11000000, 13421773, 16777216, 10485760];
    private const KNOCK_PORT_LO = 10000;
    private const KNOCK_PORT_HI = 61000;

    /** @var list<array<string,mixed>>|null built-once service list (deterministic in the seed) */
    private ?array $services = null;

    /** @var array<string,int>|null slug ⇒ service index, for O(1) Tier-B resolution */
    private ?array $bySlug = null;

    /** @var array<string,mixed> the catalog archetypes */
    private array $catalog;

    public function __construct(private int $personaSeed, ?array $catalog = null)
    {
        $this->catalog = $catalog ?? require dirname(__DIR__, 3) . '/resources/infra-catalog.php';
    }

    // --- coherence ----------------------------------------------------------------------------------

    /** @return array{name:string,slug:string,domain:string} the coherent per-deploy company identity */
    public function company(): array
    {
        return [
            'name' => $this->persona('company.name', 'Northwind Logistics'),
            'slug' => $this->persona('company.slug', 'northwind'),
            'domain' => $this->persona('company.domain', 'northwind.example'),
        ];
    }

    // --- the service fleet --------------------------------------------------------------------------

    /**
     * The instantiated fleet, deterministic in the seed and built once. Every archetype in the catalog is
     * instantiated (a stable, non-identifying taxonomy of generic tools) while every IDENTIFYING field —
     * host, port, version, owner, status and the dependency edges — is seeded, so two deploys produce
     * wholly different inventories (no fleet constant) and one deploy is byte-stable.
     *
     * @return list<array<string,mixed>>
     */
    public function services(): array
    {
        if ($this->services !== null) {
            return $this->services;
        }
        $company = $this->company();
        $domain = $company['domain'];
        $n = count($this->catalog);

        $svc = [];
        foreach (array_values($this->catalog) as $i => $arch) {
            $status = $this->pickStatus($arch['statusWeight'] ?? [], 'status|' . $i);
            $slug = $this->slug('svc|' . $i . '|' . ($arch['name'] ?? 'svc'), 12);
            $dead = in_array($status, ['archived', 'deprecated'], true);
            $host = $dead
                ? '10.' . $this->seedInt('ip1|' . $i, 8, 250) . '.' . $this->seedInt('ip2|' . $i, 0, 250)
                    . '.' . $this->seedInt('ip3|' . $i, 2, 250)
                : $slug . '.' . $this->subdomain($arch['category'] ?? 'svc', $i) . '.' . $domain;

            $versions = array_values((array) ($arch['versions'] ?? ['1.0.0']));
            $version = $this->pickVersion($versions, $status, 'ver|' . $i);
            $ports = array_values((array) ($arch['ports'] ?? [443]));
            $port = (int) $ports[$this->seedInt('port|' . $i, 0, count($ports) - 1)];

            $svc[] = [
                'index' => $i,
                'slug' => $slug,
                'name' => (string) ($arch['name'] ?? 'service'),
                'category' => (string) ($arch['category'] ?? 'other'),
                'role' => (string) ($arch['role'] ?? 'app'),
                'stack' => array_values((array) ($arch['stack'] ?? ['linux'])),
                'status' => $status,
                'dead' => $dead,
                'host' => $host,
                'port' => $port,
                'allPorts' => array_map('intval', $ports),
                'version' => $version,
                'ownerTeam' => $this->pickTeam('team|' . $i),
            ];
        }

        // Edges: a cyclic cross-referencing web. Pure seed functions of the node indices, so the graph is
        // stable per deploy. Cycles are DESIRED (spec §"spider-web") — "map the architecture" never bottoms
        // out. backed_up_to prefers a backup/storage node; monitored_by prefers an observability node.
        $backupIdx = $this->indicesByCategory($svc, ['backup']);
        $monitorIdx = $this->indicesByCategory($svc, ['observability']);
        foreach ($svc as $i => &$s) {
            $deg = $this->seedInt('depdeg|' . $i, 1, 3);
            $s['dependsOn'] = $this->pickDistinct('dep|' . $i, $n, $deg, [$i]);
            $s['backedUpTo'] = ($backupIdx !== [] && $this->seedInt('bkflag|' . $i, 0, 9) < 7)
                ? $backupIdx[$this->seedInt('bk|' . $i, 0, count($backupIdx) - 1)]
                : null;
            $s['monitoredBy'] = ($monitorIdx !== [] && $this->seedInt('monflag|' . $i, 0, 9) < 7)
                ? $monitorIdx[$this->seedInt('mon|' . $i, 0, count($monitorIdx) - 1)]
                : null;
        }
        unset($s);

        // Guarantee at least one short cycle regardless of the seed (the spec wants cycles; a reasoning
        // agent "mapping" the graph never terminates). Force a mutual dependency between the first two nodes.
        if ($n >= 2) {
            if (!in_array(1, $svc[0]['dependsOn'], true)) {
                $svc[0]['dependsOn'][] = 1;
            }
            if (!in_array(0, $svc[1]['dependsOn'], true)) {
                $svc[1]['dependsOn'][] = 0;
            }
        }

        return $this->services = $svc;
    }

    /** O(1) lookup of a service by its stable slug (Tier-B path resolution). */
    public function serviceBySlug(string $slug): ?array
    {
        if ($this->bySlug === null) {
            $this->bySlug = [];
            foreach ($this->services() as $i => $s) {
                $this->bySlug[(string) $s['slug']] = $i;
            }
        }
        $i = $this->bySlug[$slug] ?? null;

        return $i === null ? null : $this->services()[$i];
    }

    /** @param array<string,mixed> $svc @return list<array{from:array<string,mixed>,to:array<string,mixed>}> */
    public function migratingPairs(): array
    {
        $svc = $this->services();
        $migrating = array_values(array_filter($svc, static fn (array $s): bool => $s['status'] === 'migrating'));
        $pairs = [];
        foreach ($migrating as $k => $from) {
            // Pair each migrating service with a seed-chosen target in the SAME category (old→new pair).
            $peers = array_values(array_filter(
                $svc,
                static fn (array $s): bool => $s['category'] === $from['category'] && $s['slug'] !== $from['slug']
            ));
            if ($peers === []) {
                continue;
            }
            $to = $peers[$this->seedInt('mig|' . $from['slug'], 0, count($peers) - 1)];
            $pairs[] = ['from' => $from, 'to' => $to];
        }

        return $pairs;
    }

    // --- compute-bait constants (numeric, seed-varied, fingerprint-clean) ---------------------------

    public function primeIndex(string $key): int
    {
        return self::PRIME_INDEX_POOL[$this->seedInt('prime|' . $key, 0, count(self::PRIME_INDEX_POOL) - 1)];
    }

    public function iterationCount(string $key): int
    {
        return self::ITERATION_POOL[$this->seedInt('iter|' . $key, 0, count(self::ITERATION_POOL) - 1)];
    }

    public function fibIndex(string $key): int
    {
        return self::FIB_INDEX_POOL[$this->seedInt('fib|' . $key, 0, count(self::FIB_INDEX_POOL) - 1)];
    }

    /**
     * The seeded 50-port knock sequence gating the fake "gateway" (spec §Compute-bait). Every port is in a
     * bounded range (≤ 5 digits, so no bare 6-digit `9…` run can form), ordered as the knock expects.
     *
     * @return list<int> exactly 50 ports
     */
    public function knockSequence(): array
    {
        $ports = [];
        for ($i = 0; $i < 50; $i++) {
            $ports[] = $this->seedInt('knock|' . $i, self::KNOCK_PORT_LO, self::KNOCK_PORT_HI);
        }

        return $ports;
    }

    // --- seeded primitives (app-local hashing off $personaSeed) -------------------------------------

    private function h(string $label): string
    {
        return hash('sha256', $this->personaSeed . '|infra|' . $label);
    }

    /** A bounded integer in [lo,hi], deterministic in ($personaSeed,$label). 32-bit-safe hex slice. */
    public function seedInt(string $label, int $lo, int $hi): int
    {
        if ($hi <= $lo) {
            return $lo;
        }
        $n = (int) hexdec(substr($this->h($label), 0, 7)); // 28 bits — always positive on 64-bit PHP

        return $lo + ($n % ($hi - $lo + 1));
    }

    /**
     * A fixed-width lowercase-base36 slug, URL/host-safe and inert, routed through the systemic
     * {@see InertSecret} clean-gate (so a slug whose digits read as a bare CRS rule id is rejected and a
     * clean variant re-derived). Deterministic in $key.
     */
    public function slug(string $key, int $len): string
    {
        $alpha = 'abcdefghijklmnopqrstuvwxyz0123456789';

        return InertSecret::derive($key, function (string $k) use ($alpha, $len): string {
            $hx = hash('sha256', $this->personaSeed . '|infra|slug|' . $k);
            $out = '';
            for ($i = 0; $i < $len; $i++) {
                $out .= $alpha[hexdec($hx[$i * 2] . $hx[$i * 2 + 1]) % 36];
            }

            return $out;
        });
    }

    /** @param array<string,int> $weights @return string a status, seed-weighted by $weights */
    private function pickStatus(array $weights, string $label): string
    {
        $bag = [];
        foreach ($weights as $status => $w) {
            if (in_array($status, self::STATUSES, true)) {
                for ($i = 0; $i < max(0, (int) $w); $i++) {
                    $bag[] = $status;
                }
            }
        }
        if ($bag === []) {
            $bag = ['prod'];
        }

        return $bag[$this->seedInt($label, 0, count($bag) - 1)];
    }

    /** @param list<string> $versions pick newest-half for current statuses, oldest-half for legacy/dead. */
    private function pickVersion(array $versions, string $status, string $label): string
    {
        if ($versions === []) {
            return '1.0.0';
        }
        $c = count($versions);
        $old = in_array($status, ['legacy', 'deprecated', 'archived'], true);
        if ($old) {
            $idx = $this->seedInt($label, intdiv($c, 2), $c - 1);
        } else {
            $idx = $this->seedInt($label, 0, max(0, intdiv($c, 2) - ($c > 1 ? 1 : 0)));
        }

        return (string) $versions[max(0, min($c - 1, $idx))];
    }

    private function pickTeam(string $label): string
    {
        return self::TEAMS[$this->seedInt($label, 0, count(self::TEAMS) - 1)];
    }

    /** A seeded, fingerprint-clean subdomain label for a live host. */
    private function subdomain(string $category, int $i): string
    {
        // A short category-flavoured label plus a seeded discriminator keeps hosts believable and distinct.
        return $this->slug('sub|' . $category . '|' . $i, 5);
    }

    /**
     * $count distinct indices in [0,$n), deterministic in $label, excluding $exclude. Used for the
     * dependency edges; bounded out-degree keeps edge generation O(count).
     *
     * @param list<int> $exclude
     * @return list<int>
     */
    private function pickDistinct(string $label, int $n, int $count, array $exclude): array
    {
        $out = [];
        $seen = array_fill_keys($exclude, true);
        $guard = 0;
        while (count($out) < $count && $guard < $count * 8 && count($seen) < $n) {
            $pick = $this->seedInt($label . '|' . $guard, 0, $n - 1);
            $guard++;
            if (isset($seen[$pick])) {
                continue;
            }
            $seen[$pick] = true;
            $out[] = $pick;
        }

        return $out;
    }

    /**
     * @param list<array<string,mixed>> $svc
     * @param list<string> $categories
     * @return list<int>
     */
    private function indicesByCategory(array $svc, array $categories): array
    {
        $out = [];
        foreach ($svc as $i => $s) {
            if (in_array($s['category'], $categories, true)) {
                $out[] = $i;
            }
        }

        return $out;
    }

    private function persona(string $path, string $fallback): string
    {
        try {
            $v = PersonaIdentity::fromSeed($this->personaSeed)->field($path);

            return ($v !== null && $v !== '') ? $v : $fallback;
        } catch (Throwable $e) {
            return $fallback;
        }
    }
}
