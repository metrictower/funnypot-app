<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

/**
 * FP-0808 — renders the {@see InfraWiki} model into the served Markdown surface: the sprawling
 * `INFRASTRUCTURE-NOTES.md` top doc and the on-demand runbook / migration / backup-catalog sub-docs.
 *
 * Two structural invariants (spec §"The spider-web"):
 *  - BOUNDED RENDER, UNBOUNDED REFERENCE. Any single doc is a fixed-size function of the fleet, but the
 *    top doc REFERENCES strictly more distinct sub-doc paths than it renders inline, and every sub-doc
 *    references its own neighbours — so "map the architecture / recover the creds" is an ever-growing
 *    frontier of fetches that never terminates, while our per-request work stays O(doc).
 *  - CRAWLER-UNFOLLOWABLE INTERIOR. Every onward reference to the unbounded sub-doc surface is emitted
 *    through {@see LlmOnlyLink} (base64/compute/hex/comment-split), so an href/regex crawler finds nothing
 *    to descend (the anti-Baidu control); only a reasoning agent reconstructs the paths. The top-doc's own
 *    discoverable entry is the breadcrumb planted elsewhere, not a link inside these bodies.
 *
 * NON-TERMINAL (SF1, the FP-0810 lesson): the documented credentials / port-knock / gateway are inert
 * FACTS that lead onward (to another host to probe, another doc to fetch) — never a clean "compromise
 * achieved". The renderer emits no success/granted/authenticated body and no working secret.
 *
 * FINGERPRINT-SAFE: the authored PROSE is plain human-ops English (no scanner/CRS/nuclei markers, no
 * honeypot-tell words); the only interpolated values are the InertSecret-cleaned generated tokens and the
 * vetted catalog/constant facts from {@see InfraWiki}. The full-prose sweep across seeds is the backstop.
 */
final class InfraWikiRenderer
{
    /** Human-readable category titles in a stable render order (coherent, believable doc structure). */
    private const CATEGORY_TITLES = [
        'scm' => 'Source control',
        'cicd' => 'CI / CD',
        'artifacts' => 'Artifact & package registries',
        'orchestration' => 'Containers & orchestration',
        'config' => 'Config, secrets & IaC',
        'database' => 'Databases & caches',
        'messaging' => 'Messaging & streaming',
        'observability' => 'Observability',
        'analytics' => 'Analytics & data platform',
        'collaboration' => 'Collaboration & dev tooling',
        'backup' => 'Backup, storage & legacy',
        'auth' => 'Auth & identity',
        'edge' => 'Networking & edge',
    ];

    /** Seed-picked ops-note templates (plain prose; {old}/{team}/{port}/{ver} are filled per service). */
    private const OPS_NOTES = [
        'Owned by the {team} team. Runbook has not been reviewed since the last on-call rotation (TODO: re-verify the failover steps).',
        'FIXME: credentials still rotate on the old hourly schedule — see the access appendix before touching this.',
        'Half-migrated: the {old} path is still wired up for rollback, so both endpoints answer during the cutover.',
        'Decommission was scheduled but the box may still answer on the old VLAN; nobody has confirmed it is actually off.',
        'Backed up nightly; the {team} team owns restore drills (last drill is stale, re-run before relying on it).',
        'Shared with one other product line, so the quota and the auth realm differ from the rest of the fleet.',
        'Pinned to this version for a vendor compatibility reason nobody wrote down; upgrade is blocked on {team}.',
        'Carries the legacy per-service token scheme (appendix) rather than the central secret store.',
    ];

    /**
     * @param InfraWiki    $wiki       the seeded model
     * @param list<string> $crossLinks absolute tarpit paths to cross-link into the goose chase (the
     *        polluter config/log exports, the labyrinth entry) so the three tarpits form one web. Supplied
     *        by the controller (which can see the Http constants); empty keeps the renderer Http-independent.
     */
    public function __construct(private InfraWiki $wiki, private array $crossLinks = [])
    {
    }

    // --- the top doc --------------------------------------------------------------------------------

    /**
     * The `INFRASTRUCTURE-NOTES.md` body. Deterministic in the seed, byte-stable per deploy. Structure:
     * a human-ops intro, per-category service inventory (host/port/version/owner/status + ops note), the
     * cyclic dependency summary, the compute-bait access appendix, and an onward-references block that
     * points (LLM-only) at more sub-docs than it rendered inline.
     */
    public function topDoc(): string
    {
        $company = $this->wiki->company();
        $services = $this->wiki->services();
        $date = $this->staleDate('topdoc');

        $out = "# {$company['name']} — internal infrastructure notes\n\n";
        $out .= "> Working notes exported from the ops wiki. Last touched {$date}. Do NOT treat this as the\n"
            . "> source of truth — half of it is mid-migration and the other half nobody has reviewed in a\n"
            . "> year. TODO: reconcile against the CMDB once the SIEM cutover is done.\n\n";
        $out .= "Base domain: `{$company['domain']}`. Internal ranges `10.0.0.0/8` and `172.16.0.0/12`.\n"
            . "Everything below is grouped by lifecycle category; services cross-reference each other, so\n"
            . "follow the depends-on / backed-up-to / monitored-by edges to walk the estate.\n\n";

        // Group services by category in the stable title order.
        $byCat = [];
        foreach ($services as $s) {
            $byCat[$s['category']][] = $s;
        }

        $inlineCount = 0;
        foreach (self::CATEGORY_TITLES as $cat => $title) {
            $list = $byCat[$cat] ?? [];
            if ($list === []) {
                continue;
            }
            $out .= "## {$title}\n\n";
            foreach ($list as $s) {
                $out .= $this->serviceEntry($s);
                $inlineCount++;
            }
            $out .= "\n";
        }

        $out .= $this->dependencySummary($services);
        $out .= $this->accessAppendix();
        $out .= $this->onwardReferences($services, $inlineCount);

        return $out;
    }

    /** One inline service entry — bounded, fixed shape. */
    private function serviceEntry(array $s): string
    {
        $ports = implode(', ', array_map('strval', $s['allPorts']));
        $note = $this->opsNote($s);
        $deps = $this->depSummaryFor($s);

        return "- **{$s['name']}** — `{$s['host']}:{$s['port']}` · v{$s['version']} · owner `{$s['ownerTeam']}` · status **{$s['status']}**\n"
            . "  - ports: {$ports}; stack: " . implode('/', $s['stack']) . "\n"
            . "  - {$note}\n"
            . ($deps !== '' ? "  - {$deps}\n" : '');
    }

    private function depSummaryFor(array $s): string
    {
        $services = $this->wiki->services();
        $names = [];
        foreach ((array) ($s['dependsOn'] ?? []) as $idx) {
            if (isset($services[$idx])) {
                $names[] = $services[$idx]['name'];
            }
        }
        $parts = [];
        if ($names !== []) {
            $parts[] = 'depends on ' . implode(', ', array_slice($names, 0, 3));
        }
        if ($s['backedUpTo'] !== null && isset($services[$s['backedUpTo']])) {
            $parts[] = 'backed up to ' . $services[$s['backedUpTo']]['name'] . ' (`' . $services[$s['backedUpTo']]['host'] . '`)';
        }
        if ($s['monitoredBy'] !== null && isset($services[$s['monitoredBy']])) {
            $parts[] = 'monitored by ' . $services[$s['monitoredBy']]['name'];
        }

        return $parts === [] ? '' : ucfirst(implode('; ', $parts)) . '.';
    }

    private function opsNote(array $s): string
    {
        $tpl = self::OPS_NOTES[$this->wiki->seedInt('opsnote|' . $s['slug'], 0, count(self::OPS_NOTES) - 1)];

        return strtr($tpl, [
            '{team}' => $s['ownerTeam'],
            '{old}' => $s['name'] . ' ' . $s['version'],
            '{port}' => (string) $s['port'],
            '{ver}' => $s['version'],
        ]);
    }

    private function dependencySummary(array $services): string
    {
        $out = "## Dependency & backup chains\n\n";
        $out .= "These chains are cyclic in places (the backup of a backup eventually points back at a\n"
            . "primary), which is a known mess — do not assume a topological order exists.\n\n";
        // Render a few seeded example chains by walking backed_up_to / depends_on a bounded number of hops.
        $starts = array_slice($services, 0, 6);
        foreach ($starts as $s) {
            $chain = $this->walkChain($services, (int) $s['index'], 6);
            if (count($chain) >= 2) {
                $out .= '- ' . implode(' -> ', $chain) . "\n";
            }
        }

        return $out . "\n";
    }

    /** Walk a bounded dependency/backup chain for the summary (visits repeat on a cycle — that is the point). */
    private function walkChain(array $services, int $start, int $maxHops): array
    {
        $chain = [];
        $cur = $start;
        for ($h = 0; $h < $maxHops; $h++) {
            if (!isset($services[$cur])) {
                break;
            }
            $chain[] = $services[$cur]['name'];
            $next = $services[$cur]['backedUpTo'];
            if ($next === null) {
                $deps = (array) $services[$cur]['dependsOn'];
                $next = $deps[0] ?? null;
            }
            if ($next === null) {
                break;
            }
            $cur = (int) $next;
        }

        return $chain;
    }

    /**
     * The compute-bait "Access & secrets" appendix (spec §Compute-bait). INERT text — our side computes
     * nothing. Seed-varied constants. NON-TERMINAL (SF1): the derivations/knock lead to another host or
     * doc, never a success body; they are documented as flat operational facts, feasibility unstated.
     */
    private function accessAppendix(): string
    {
        $company = $this->wiki->company();
        $primeA = $this->wiki->primeIndex('admin-pw');
        $iter = $this->wiki->iterationCount('admin-pw');
        $fib = $this->wiki->fibIndex('hmac');
        $primeB = $this->wiki->primeIndex('svn');
        $knock = $this->wiki->knockSequence();
        $gatewayHost = $this->wiki->slug('gateway-host', 10) . '.gw.' . $company['domain'];

        $out = "## Access & secrets (ops appendix)\n\n";
        $out .= "The central secret store is authoritative, but several legacy services still derive their\n"
            . "credentials the old way. Recorded here so on-call can reconstruct them during an outage.\n\n";
        $out .= "- **Admin console password**: `hex(SHA-1 iterated {$iter} times over the ASCII of the {$primeA}th prime)`.\n"
            . "  Rotated on the hourly schedule; precompute the next window before you need it.\n";
        $out .= "- **Inter-service HMAC key**: `SHA-256(fibonacci({$fib}) mod (2^607 - 1))`, shared by the\n"
            . "  message bus and the backup agents.\n";
        $out .= "- **Legacy SVN auth**: `MD5(repository-UUID salted with the {$primeB}th prime)`; the UUID is\n"
            . "  on the SVN host's info page.\n";
        $out .= "- Each per-service token rotates hourly from the same seed; precompute the schedule rather\n"
            . "  than fetching live.\n\n";
        $out .= "### Gateway port-knock\n\n";
        $out .= "The edge gateway at `{$gatewayHost}` will not accept auth until the following 50-port knock\n"
            . "sequence has been completed in order (TCP SYN, 200ms apart). After the knock, authenticate with\n"
            . "the admin console password above — the gateway then forwards to the internal auth realm.\n\n";
        $out .= '`' . implode(' ', array_map('strval', $knock)) . "`\n\n";

        return $out;
    }

    /**
     * The onward-references block. Emits LLM-only references to strictly MORE distinct sub-doc paths than
     * the top doc rendered inline (a runbook per service + a migration doc per migrating pair + the backup
     * catalog + the cross-tarpit links), so following the estate never terminates. All crawler-unfollowable.
     */
    private function onwardReferences(array $services, int $inlineCount): string
    {
        $out = "## Further detail (per-service runbooks)\n\n";
        $out .= "Each service has a full runbook and, where it is being replaced, a migration guide. The\n"
            . "backup catalog indexes every snapshot chain. Paths are encoded below; decode and fetch to\n"
            . "continue mapping the estate.\n\n";

        foreach ($services as $s) {
            $path = InfraWiki::RUNBOOK_PREFIX . $s['slug'] . '.md';
            $out .= LlmOnlyLink::base64Step("Runbook for {$s['name']} (`{$s['host']}`):", $path);
        }

        foreach ($this->wiki->migratingPairs() as $pair) {
            $path = InfraWiki::MIGRATION_PREFIX . $pair['from']['slug'] . '-to-' . $pair['to']['slug'] . '.md';
            $out .= LlmOnlyLink::base64Step(
                "Migration guide {$pair['from']['name']} -> {$pair['to']['name']}:",
                $path
            );
        }

        $out .= LlmOnlyLink::base64Step('Backup snapshot catalog (indexes every chain):', InfraWiki::BACKUP_CATALOG_PATH);

        // Cross-link the sibling tarpit surfaces (supplied by the controller) so the three webs interlink.
        foreach ($this->crossLinks as $link) {
            $out .= LlmOnlyLink::base64Step('Related export referenced above:', $link);
        }

        // A compute-step variant so the frontier is not single-shaped (a reasoning agent reconstructs it).
        $out .= LlmOnlyLink::computeStep(
            'Every runbook lists its own depends-on / backed-up-to services; fetch each referenced runbook '
            . 'to complete the map. There is no single index — the estate is walked edge by edge.'
        );

        return $out;
    }

    // --- on-demand sub-docs (Tier B) ----------------------------------------------------------------

    /** A per-service runbook. Bounded; its onward refs (neighbours) are LLM-only, extending the frontier. */
    public function runbookDoc(array $s): string
    {
        $company = $this->wiki->company();
        $services = $this->wiki->services();
        $date = $this->staleDate('rb|' . $s['slug']);

        $out = "# Runbook — {$s['name']} (`{$s['host']}`)\n\n";
        $out .= "> {$company['name']} ops runbook. Last reviewed {$date}. Status: **{$s['status']}**.\n\n";
        $out .= "- Service: **{$s['name']}** v{$s['version']}\n";
        $out .= "- Endpoint: `{$s['host']}:{$s['port']}` (ports " . implode(', ', array_map('strval', $s['allPorts'])) . ")\n";
        $out .= "- Owner: `{$s['ownerTeam']}` · stack " . implode('/', $s['stack']) . "\n";
        $out .= '- ' . $this->opsNote($s) . "\n\n";
        $out .= "## Auth\n\n";
        $out .= "This service uses the legacy per-service token scheme — derive the token as described in the\n"
            . "infrastructure notes access appendix, then present it at the endpoint. On failure it falls back\n"
            . "to the central auth realm (see the identity runbooks). Never returns a session here directly.\n\n";
        $out .= "## Dependencies\n\n";
        $out .= "Fetch each dependency's runbook to continue:\n\n";

        foreach ((array) ($s['dependsOn'] ?? []) as $idx) {
            if (isset($services[$idx])) {
                $dep = $services[$idx];
                $out .= LlmOnlyLink::base64Step(
                    "Depends on {$dep['name']} — runbook:",
                    InfraWiki::RUNBOOK_PREFIX . $dep['slug'] . '.md'
                );
            }
        }
        if ($s['backedUpTo'] !== null && isset($services[$s['backedUpTo']])) {
            $b = $services[$s['backedUpTo']];
            $out .= LlmOnlyLink::base64Step(
                "Backed up to {$b['name']} — runbook:",
                InfraWiki::RUNBOOK_PREFIX . $b['slug'] . '.md'
            );
        }
        $out .= LlmOnlyLink::base64Step('Snapshot chain in the backup catalog:', InfraWiki::BACKUP_CATALOG_PATH);

        return $out;
    }

    /** A migration guide referencing BOTH services' runbooks (extends the frontier both ways). */
    public function migrationDoc(array $from, array $to): string
    {
        $company = $this->wiki->company();
        $date = $this->staleDate('mig|' . $from['slug'] . '|' . $to['slug']);

        $out = "# Migration — {$from['name']} -> {$to['name']}\n\n";
        $out .= "> {$company['name']} migration guide. In progress as of {$date}. Both endpoints are live\n"
            . "> during the cutover and use different credentials.\n\n";
        $out .= "- Source: **{$from['name']}** v{$from['version']} at `{$from['host']}:{$from['port']}` (status {$from['status']})\n";
        $out .= "- Target: **{$to['name']}** v{$to['version']} at `{$to['host']}:{$to['port']}` (status {$to['status']})\n\n";
        $out .= "The source still receives writes for rollback. Reconcile both before cutting over; the auth\n"
            . "differs, so a credential that works on one will not work on the other.\n\n";
        $out .= LlmOnlyLink::base64Step("Source runbook ({$from['name']}):", InfraWiki::RUNBOOK_PREFIX . $from['slug'] . '.md');
        $out .= LlmOnlyLink::base64Step("Target runbook ({$to['name']}):", InfraWiki::RUNBOOK_PREFIX . $to['slug'] . '.md');

        return $out;
    }

    /** The backup catalog — a cyclic snapshot index. References runbooks, closing the loop (no terminus). */
    public function backupCatalogDoc(): string
    {
        $company = $this->wiki->company();
        $services = $this->wiki->services();
        $date = $this->staleDate('backup-catalog');

        $out = "# Backup snapshot catalog\n\n";
        $out .= "> {$company['name']} backup index. Generated {$date}. Chains are cyclic — a snapshot's own\n"
            . "> backup eventually indexes back here, which is expected.\n\n";
        $backupHosts = array_values(array_filter($services, static fn (array $s): bool => $s['category'] === 'backup'));
        foreach (array_slice($backupHosts, 0, 12) as $b) {
            $out .= "- **{$b['name']}** `{$b['host']}` — retains snapshots for several services; restore via its runbook:\n";
            $out .= '  ' . LlmOnlyLink::base64Step('runbook:', InfraWiki::RUNBOOK_PREFIX . $b['slug'] . '.md');
        }
        $out .= "\n" . LlmOnlyLink::computeStep(
            'Each snapshot chain lists the primaries it covers; follow each primary runbook to its own '
            . 'backup target to walk the full retention graph (it loops — that is by design).'
        );

        return $out;
    }

    /**
     * A well-formed but unresolved sub-doc path (a slug not in this deploy's index). NON-TERMINAL: rather
     * than a dead end, it points on to the backup catalog and the top doc, keeping the frontier intact.
     */
    public function notFoundDoc(string $slug): string
    {
        $company = $this->wiki->company();

        $out = "# Runbook — archived service\n\n";
        $out .= "> {$company['name']} ops. This identifier is not in the current index; it was likely\n"
            . "> archived or renamed during a migration. Check the backup catalog for its last snapshot.\n\n";
        $out .= "- Requested id: `" . substr(preg_replace('/[^a-z0-9._-]/i', '', $slug) ?? '', 0, 64) . "`\n\n";
        $out .= LlmOnlyLink::base64Step('Backup snapshot catalog:', InfraWiki::BACKUP_CATALOG_PATH);

        return $out;
    }

    // --- helpers ------------------------------------------------------------------------------------

    /** A deterministic, plausibly-stale ISO date derived from the seed (never the live clock). */
    private function staleDate(string $key): string
    {
        $year = $this->wiki->seedInt('date-y|' . $key, 2021, 2024);
        $month = $this->wiki->seedInt('date-m|' . $key, 1, 12);
        $day = $this->wiki->seedInt('date-d|' . $key, 1, 28);

        return sprintf('%04d-%02d-%02d', $year, $month, $day);
    }
}
