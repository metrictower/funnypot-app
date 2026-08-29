<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Storage\FakePersistenceStore;
use Funnypot\Core\RequestContext;

/**
 * Request-scoped facade over FakePersistenceStore for the deep panel's fake persistence layer. Bound to
 * one visitor (ip + persona seed), it is the single place that knows WHICH panel endpoints accept a
 * write and under which view key each visitor's submission is echoed back — so capture (responder side)
 * and echo (section side) always agree on the key.
 *
 * Reversal of spec E6's "never persist": a scanner testing STORED vulns writes a note/message/edit and
 * re-polls to confirm it landed. Echoing the submitted text (HTML-escaped by the section, never raw)
 * makes the panel look stateful and deepens the trap. The E6 carve-out still holds: PINs/access codes
 * are never among the captured fields, so they are still never reflected.
 */
final class FakePersistence
{
    public function __construct(private FakePersistenceStore $store, private string $ip, private int $seed)
    {
    }

    /** View key for an HR profile edit — the "saved" landing and edit form echo the submitted values. */
    public static function hrEditKey(string $empId): string
    {
        return 'hr/edit/' . $empId;
    }

    /** View key for a digital-signage broadcast — the "message pushed" leaf echoes the pushed text. */
    public static function signageMessageKey(string $scope): string
    {
        return 'signage/msg/' . $scope;
    }

    /**
     * True for panel paths that participate in fake persistence. The responder uses this to keep such
     * a view OUT of the byte-identical panel cache: a per-visitor echo must never be frozen or served
     * to another ip.
     */
    public static function isPersistablePath(string $path): bool
    {
        return self::viewFor($path) !== null;
    }

    /**
     * If this is a POST to a recognised write endpoint, capture its whitelisted fields and record them
     * under the view's key. Only ever reads the request's own body; a non-write request is a no-op.
     */
    public function capture(RequestContext $ctx): void
    {
        if (strtoupper($ctx->method) !== 'POST') {
            return;
        }
        $view = self::viewFor($ctx->path);
        if ($view === null) {
            return;
        }
        $fields = self::extractFields($ctx->rawBody, $view['fields']);
        if ($fields === []) {
            return;
        }
        $this->store->record($this->ip, $this->seed, $view['key'], $fields);
    }

    /**
     * Submissions previously stored for a view (newest first), for a section to echo (escaped).
     *
     * @return list<array<string,string>>
     */
    public function items(string $viewKey): array
    {
        return $this->store->read($this->ip, $this->seed, $viewKey);
    }

    /**
     * Map a panel path to its persistence view: the view key both sides share and the field names a
     * write to it may capture. Null for any path that does not participate.
     *
     * @return array{key:string,fields:list<string>}|null
     */
    private static function viewFor(string $path): ?array
    {
        $r = PanelRoute::parse($path);

        // HR profile edit — the inert form POSTs to /edit/saved; the "saved" landing (and the form on a
        // re-visit) reflect the submitted title/location. Never captures a sensitive field.
        if ($r['module'] === 'hr' && $r['section'] === 'employees'
            && strncmp($r['entity'], 'emp-', 4) === 0 && $r['subtab'] === 'edit') {
            return ['key' => self::hrEditKey($r['entity']), 'fields' => ['title', 'location']];
        }

        // Digital-signage broadcast — the "message pushed" leaf reflects the pushed text.
        if ($r['module'] === 'appliances' && $r['section'] === 'signage'
            && $r['subtab'] === 'message' && $r['entity'] !== '') {
            return ['key' => self::signageMessageKey($r['entity']), 'fields' => ['message']];
        }

        return null;
    }

    /**
     * Pull the whitelisted fields out of a form-urlencoded or JSON body. Only named fields are read;
     * anything else in the body is ignored, so the capture surface is exactly the endpoint's inputs.
     *
     * @param list<string> $whitelist
     * @return array<string,string>
     */
    private static function extractFields(?string $body, array $whitelist): array
    {
        if ($body === null || $body === '') {
            return [];
        }
        $parsed = [];
        if (($body[0] ?? '') === '{' || strncmp(ltrim($body), '{', 1) === 0) {
            $json = json_decode($body, true);
            if (is_array($json)) {
                $parsed = $json;
            }
        }
        if ($parsed === []) {
            @parse_str($body, $parsed);
        }

        $out = [];
        foreach ($whitelist as $name) {
            if (isset($parsed[$name]) && is_scalar($parsed[$name]) && (string) $parsed[$name] !== '') {
                $out[$name] = (string) $parsed[$name];
            }
        }

        return $out;
    }
}
