<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Storage\SsrfDecision;
use Funnypot\App\Storage\SsrfKeyIndex;
use Funnypot\App\Storage\SsrfOutcome;
use Funnypot\App\Storage\SsrfStore;
use Funnypot\App\Storage\SsrfTx;
use Funnypot\App\Storage\TokenMintTx;
use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\Mint\CsrfCodec;
use Funnypot\App\Tarpit\Mint\DecoyPrincipalResolver;
use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Mint\MintContext;
use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\App\Tarpit\Mint\MintRequest;
use Funnypot\App\Tarpit\Mint\MintState;
use Funnypot\App\Tarpit\Mint\MintVocabulary;
use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\Core\RequestContext;
use Throwable;

/**
 * The SSRF proof-bait surface: account webhooks with test deliveries and redeliveries, imports from a
 * URL (orders files and Git mirrors) and an S3-compatible export destination with "verify connection",
 * on the token-mint account. Every delivery is fake: the fake network decides where a request would
 * have gone and what it would have got, and nothing is ever fetched, resolved or connected to.
 *
 * It joins HoneypotController at the same serve seam as the token-mint surface, after it, for a
 * disjoint closed path set: detection, the hit row and reports are built exactly as for any request,
 * and only the serve branch is replaced. owns() is a function of the path alone. prepare() returns null
 * for any other path and when its own code fails for a reason other than the store (the controller then
 * serves today's answer); faults() counts those.
 *
 * The UI needs a live token-mint session; the API needs a personal or OAuth token with the matching
 * scope (webhooks:write, imports:write, storage:write). Each account's state is keyed by its token-mint
 * row, that row's epoch and the account serial, so a new row on the same source never sees an old one's
 * hooks. Every request runs in one store transaction that charges the source's units first; a source
 * over UNITS_PER_HOUR gets a 429. Nothing here reads a clock but the token-mint surface's injected one.
 */
final class SsrfDecoy implements SsrfDecision
{
    public const UNITS_PER_HOUR = 1200;
    public const COST_GET = 1;
    public const COST_POST = 3;
    public const COST_API = 1;
    public const COST_SEND = 4;
    public const TOUCH_S = 3600;

    /** Routes that send a fake request (and so cost more and count toward the ten-minute rate). */
    private const SEND_ROUTES = ['hook_ping', 'hook_redeliver', 'import_retry', 'storage_verify', 'api_hook_ping', 'api_redeliver', 'api_storage_verify'];

    private MintContext $c;
    private SsrfRoutes $routes;
    private DecoyPrincipalResolver $principals;
    private SsrfPages $pages;
    private FakeFetch $fetch;
    private SsrfIds $ids;
    private string $headerSlug;
    private ?IssuedValue $issued = null;

    /** @var array{0:MintRequest,1:array<string,mixed>,2:string,3:int,4:int,5:bool}|null the request a store transaction is deciding */
    private ?array $pending = null;
    private int $faults = 0;
    private ?Throwable $lastFault = null;

    public function __construct(
        private TokenMintDecoy $mint,
        private SsrfStore $store,
        private KeyIndexView $index,
        private Network $net,
        private ServedKeys $keys,
        private SsrfKeys $sk,
        private bool $denylist = true,
    ) {
        $this->c = $mint->context();
        $this->routes = new SsrfRoutes();
        $this->principals = new DecoyPrincipalResolver($this->c);
        $this->pages = new SsrfPages($this->c->pages, $this->c->persona->company);
        $this->fetch = new FakeFetch(new NodeAnswers($net, $this->c->persona->company), $this->sk->key('rid'));
        $this->ids = new SsrfIds($sk);
        $this->headerSlug = ucfirst((string) preg_replace('/[^A-Za-z0-9-]/', '', $this->c->persona->slug));
    }

    /**
     * The decoy for a deploy. The token-mint decoy must already be built with SsrfRoutes::extension().
     *
     * @param list<HostDirectory> $extraHosts providers another surface adds (the infra wiki, once wired)
     */
    public static function build(
        TokenMintDecoy $mint,
        string $tokenMintKey,
        int $personaSeed,
        SsrfStore $store,
        string $indexPath,
        string $renderSalt,
        string $filesystemKey,
        int $capBytes,
        bool $credPointers,
        bool $denylist,
        string $buildStamp,
        array $extraHosts = [],
    ): self {
        $sk = new SsrfKeys($tokenMintKey);
        $index = new SsrfKeyIndex(
            $indexPath,
            $sk->key('keyidx'),
            new KeyIndexBuilder($personaSeed, $filesystemKey, $capBytes),
            SsrfKeyIndex::deployId($sk->key('keyidx'), $personaSeed, $capBytes, $credPointers, $buildStamp, $filesystemKey),
        );
        $net = Network::build($sk, $personaSeed, $capBytes, $index, $credPointers, $extraHosts);

        return new self($mint, $store, $index, $net, new ServedKeys($personaSeed, $renderSalt, $index), $sk, $denylist);
    }

    public function owns(string $path): bool
    {
        return $this->routes->owns($path);
    }

    public function index(): KeyIndexView
    {
        return $this->index;
    }

    public function network(): Network
    {
        return $this->net;
    }

    public function prepare(RequestContext $ctx, string $ip, ?IssuedValue $issued = null): ?MintPlan
    {
        $match = $this->routes->match($ctx->path);
        if ($match === null) {
            return null;
        }
        $this->issued = $issued;
        $this->c->issuingWith($issued);
        try {
            $r = MintRequest::parse($ctx, $match, $ip);
            $plan = $this->dispatch($r, $ip);
            $plan->attribute(['route' => $r->route]);
            if ($r->pattern && TokenMintDecoy::nonDisclosing($plan)
                && !(in_array($plan->status, [422, 429], true) && $this->c->csrf->issuedByUs($r->str(CsrfCodec::FIELD)))) {
                $plan->served = false;
            }

            return $r->isHead() ? $plan->forHead() : $plan;
        } catch (Throwable $e) {
            $this->faults++;
            $this->lastFault = $e;
            error_log(sprintf('funnypot: ssrf-decoy prepare fault %s at %s:%d (code=ssrf-decoy-fault)', get_class($e), basename($e->getFile()), $e->getLine()));

            return null;
        } finally {
            $this->c->issuingWith(null);
            $this->issued = null;
        }
    }

    public function emit(MintPlan $plan): void
    {
        $this->mint->emit($plan);
    }

    public function notServed(string $ip): void
    {
        $this->mint->notServed($ip);
    }

    public function attribute(MintPlan $plan, string $ip): void
    {
        $this->store->attribute(substr($this->sk->ledger($ip), 0, 16), $this->c->now(), $plan->turn);
    }

    public function faults(): int
    {
        return $this->faults;
    }

    public function lastFault(): ?Throwable
    {
        return $this->lastFault;
    }

    private function iv(): IssuedValue
    {
        if ($this->issued === null) {
            throw new \LogicException('issuing needs the engine check');
        }

        return $this->issued;
    }

    // --- dispatch ----------------------------------------------------------------------------------

    private function dispatch(MintRequest $r, string $ip): MintPlan
    {
        $allowed = $r->methods;
        if (in_array('GET', $allowed, true)) {
            $allowed[] = 'HEAD';
        }
        if ($r->method === 'OPTIONS') {
            return MintPlan::empty(204, $r->api ? MintPlan::JSON : MintPlan::HTML)->with('Allow', implode(', ', [...$allowed, 'OPTIONS']));
        }
        if (!in_array($r->method, $allowed, true)) {
            $plan = $r->api ? MintPlan::json(405, ['message' => 'Method not allowed']) : MintPlan::html(405, $this->c->pages->methodNotAllowed($this->c->signedIn($r)));

            return $plan->with('Allow', implode(', ', $allowed))->attribute(['outcome' => 'method']);
        }
        if ($r->tooLarge) {
            return ($r->api ? MintPlan::json(413, ['message' => 'Request body too large']) : MintPlan::html(413, $this->c->pages->error('Request too large', 'The request body is too large.', '/', 'Go home', $this->c->signedIn($r))))
                ->attribute(['outcome' => 'too_large']);
        }

        return $r->api ? $this->api($r, $ip) : $this->ui($r, $ip);
    }

    private function throttled(int $retry, bool $json, string $outcome): MintPlan
    {
        $text = 'Too many requests. Try again in ' . max(1, intdiv($retry + 59, 60)) . ' minutes.';
        $plan = $json ? MintPlan::json(429, ['message' => $text]) : MintPlan::html(429, $this->pages->error('Too many requests', $text, '/settings/webhooks'));

        return $plan->with('Retry-After', (string) $retry)->attribute(['outcome' => $outcome]);
    }

    /** The units a request costs, charged before any work; zero once a source is already over its hour. */
    private function cost(MintRequest $r): int
    {
        $send = in_array($r->route, self::SEND_ROUTES, true) || (in_array($r->route, ['imports', 'api_imports'], true) && $r->method === 'POST');

        return $send ? self::COST_SEND : ($r->api ? self::COST_API : ($r->readMethod() === 'GET' ? self::COST_GET : self::COST_POST));
    }

    /**
     * Run a request's decision inside one store transaction: charge, throttle, decide.
     *
     * @param array<string,mixed> $who
     * @return array{ok:bool,failure:?string,value:mixed}
     */
    private function transact(MintRequest $r, array $who, string $ip, int $now): array
    {
        $this->index->advance($now);
        $this->pending = [$r, $who, $ip, $now, $this->cost($r), $r->readMethod() !== 'GET'];
        try {
            return $this->store->transact((string) $who['owner'], $this->sk->ledger($ip), $now, $this);
        } finally {
            $this->pending = null;
        }
    }

    /** The store transaction's decision for the pending request: charge first, then throttle, then route. */
    public function decide(?SsrfState $state, SsrfTx $tx): SsrfOutcome
    {
        if ($this->pending === null) {
            throw new \LogicException('no request is pending');
        }
        [$r, $who, $ip, $now, $cost, $changes] = $this->pending;
        $units = $tx->unitsUsed > self::UNITS_PER_HOUR ? 0 : $cost;
        if ($tx->unitsUsed + $cost > self::UNITS_PER_HOUR) {
            return new SsrfOutcome(null, false, $units, $this->throttled(3600 - $now % 3600, $r->api, 'ledger_429'));
        }
        if ($changes && $tx->capReached) {
            return new SsrfOutcome(null, false, $units, $this->throttled(300, $r->api, 'cap'));
        }
        [$plan, $next, $change] = $r->api ? $this->apiRoute($r, $state, $who, $ip, $now) : $this->uiRoute($r, $state, $who, $ip, $now);

        return new SsrfOutcome($next, $change, $units, $plan);
    }

    // --- UI ----------------------------------------------------------------------------------------

    private function ui(MintRequest $r, string $ip): MintPlan
    {
        $now = $this->c->now();
        $who = $this->principals->resolve($r);
        if ($who === null || $who['kind'] !== 'session') {
            return MintPlan::redirect('/', $this->c->persona, !$r->pattern)->attribute(['outcome' => 'no_session']);
        }
        $who['owner'] = $this->sk->owner($who['k'], $who['epoch'], $who['acct']);
        $res = $this->transact($r, $who, $ip, $now);
        if ($res['ok']) {
            return $res['value'];
        }
        if ($res['failure'] === SsrfStore::FAIL_CAP) {
            return $this->throttled(300, false, 'cap');
        }
        if ($r->method === 'POST') {
            return MintPlan::html(422, $this->pages->error('Something went wrong', "We couldn't save your changes. Try again in a moment.", '/settings/webhooks'))->attribute(['outcome' => 'store_busy']);
        }

        return $this->uiRoute($r, $this->store->load($who['owner']), $who, $ip, $now)[0];
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} [plan, state to write, state change] */
    private function uiRoute(MintRequest $r, ?SsrfState $s, array $who, string $ip, int $now): array
    {
        $post = $r->method === 'POST';
        $form = [
            'hooks' => 'hook_create', 'hook_show' => 'hook_edit', 'hook_ping' => 'hook_ping', 'hook_redeliver' => 'hook_redeliver', 'hook_delete' => 'hook_delete',
            'imports' => 'import_create', 'import_retry' => 'import_retry', 'storage' => 'storage_save', 'storage_verify' => 'storage_verify',
        ][$r->route] ?? null;
        if ($post && $form !== null && $this->c->csrf->verify($r->str(CsrfCodec::FIELD), (string) hex2bin($who['sid']), $form, $who['ce'], $now) === null) {
            return [MintPlan::html(422, $this->pages->error('This form has expired', 'Reload the page and submit the form again.', '/settings/webhooks'))->attribute(['outcome' => 'csrf']), null, false];
        }
        $st = $s ?? SsrfState::fresh($now);
        $id = $r->id();

        return match ($r->route . ($post ? ' POST' : '')) {
            'hooks' => [MintPlan::html(200, $this->pages->hooks($this->hookRows($st, $now), null)), null, false],
            'hook_new' => [MintPlan::html(200, $this->pages->hookNew($this->form($who, 'hook_create', $now), [], [])), null, false],
            'hooks POST' => $this->hookCreate($r, $st, $who, $ip, $now, false),
            'hook_show' => $this->hookShowPage($st, $id, $who, $now, [], null),
            'hook_show POST' => $this->hookEdit($r, $st, $id, $who, $ip, $now, false),
            'hook_ping POST' => $this->ping($st, $id, $who, $ip, $now, false),
            'hook_redeliver POST' => $this->redeliver($r, $st, $id, null, $who, $ip, $now, false),
            'hook_delete POST' => $this->hookDelete($st, $id, $now, false),
            'delivery_view' => $this->deliveryView($st, $id, (string) ($r->params['did'] ?? ''), $who, $now, false),
            'imports' => [MintPlan::html(200, $this->pages->imports($this->importRows($st, $now), null)), null, false],
            'import_new' => [MintPlan::html(200, $this->pages->importNew($this->form($who, 'import_create', $now), 'orders_csv', [])), null, false],
            'imports POST' => $this->importCreate($r, $st, $who, $ip, $now, false),
            'import_view' => $this->importView($st, $id, $who, $now, false),
            'import_retry POST' => $this->importRetry($st, $id, $ip, $now, false),
            'storage' => [$this->storagePage($st, $who, $now, [], [], null, 200), null, false],
            'storage POST' => $this->storageSave($r, $st, $who, $ip, $now, false),
            'storage_verify POST' => $this->storageVerify($st, $who, $ip, $now, false),
            default => [$this->notFound(false), null, false],
        };
    }

    private function form(array $who, string $formId, int $now, string $id = ''): string
    {
        return $this->c->csrfToken((string) hex2bin($who['sid']), $formId, $who['ce'], $now, $id);
    }

    private function notFound(bool $json): MintPlan
    {
        return ($json ? MintPlan::json(404, ['message' => 'Not Found']) : MintPlan::html(404, $this->pages->notFound()))->attribute(['outcome' => 'not_found']);
    }

    private function redirect(string $to): MintPlan
    {
        return MintPlan::redirect($to, $this->c->persona, true, $this->c->ext->locations);
    }

    /**
     * A validation answer: the re-rendered form for the UI, a 422 error list for the API.
     *
     * @param array<string,string> $errors
     * @return array{0:MintPlan,1:null,2:false}
     */
    private function invalid(bool $json, array $errors, ?MintPlan $page): array
    {
        if (!$json && $page !== null) {
            return [$page->attribute(['outcome' => 'validation']), null, false];
        }
        $list = [];
        foreach ($errors as $field => $key) {
            $allowed = SsrfForms::allowed($key);
            $list[] = ['field' => $field, 'code' => $key, 'message' => SsrfForms::apiMessage($key)] + ($allowed !== null ? ['allowed_values' => $allowed] : []);
        }

        return [MintPlan::json(422, ['message' => 'Validation failed', 'errors' => $list])->attribute(['outcome' => 'validation']), null, false];
    }

    // --- hooks -------------------------------------------------------------------------------------

    /** @return list<array{id:string,url:string,active:bool,last:string}> */
    private function hookRows(SsrfState $s, int $now): array
    {
        $out = [];
        foreach ($s->d['h'] as $h) {
            $last = $h['d'] !== [] ? $h['d'][count($h['d']) - 1] : null;
            $out[] = [
                'id' => (string) $h['id'],
                'url' => (string) $h['u'][count($h['u']) - 1]['url'],
                'active' => (int) $h['a'] === 1,
                'last' => $last === null ? 'Never' : SsrfPages::statusLabel($this->fetch->delivery($last['f'], (int) $last['c'], $now, (string) $last['id'])),
            ];
        }

        return $out;
    }

    /** The hook fields a create or edit sends, validated; $partial keeps absent fields (an API PATCH). */
    private function hookFields(MintRequest $r, bool $json, bool $partial): array
    {
        $errors = [];
        $vals = [];
        $urlField = $json ? 'url' : 'payload_url';
        foreach (['content_type', 'secret', 'events', 'active'] as $field) {
            if ($partial && !array_key_exists($field, $r->body)) {
                continue;
            }
            $v = $r->body[$field] ?? null;
            [$vals[$field], $err] = match ($field) {
                'content_type' => SsrfForms::contentType($v),
                'secret' => SsrfForms::secret($v),
                'events' => SsrfForms::events($v),
                default => SsrfForms::active($v),
            };
            if ($err !== null) {
                $errors[$field] = $err;
            }
        }
        $raw = $r->body[$urlField] ?? null;

        return [$vals, $errors, $urlField, $raw];
    }

    /** @return array<string,mixed> a URL version: the masked URL and its credential reference */
    private function version(Target $t, string $url, string $ip): array
    {
        return ['url' => substr(TargetParser::mask($url), 0, SsrfState::MAX_URL), 'cr' => $this->keys->reference($t, $ip)];
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function hookCreate(MintRequest $r, SsrfState $s, array $who, string $ip, int $now, bool $json): array
    {
        [$vals, $errors, $urlField, $raw] = $this->hookFields($r, $json, false);
        [$t, $urlErr] = SsrfForms::url($raw, $this->denylist);
        if ($urlErr !== null) {
            $errors[$urlField] = $urlErr;
        }
        if (count($s->d['h']) >= SsrfState::MAX_HOOKS) {
            $errors['hook'] = 'hooks_full';
        }
        if ($errors !== [] || $t === null) {
            $refill = array_diff_key($vals, ['secret' => true]);

            return $this->invalid($json, $errors, $json ? null : MintPlan::html(422, $this->pages->hookNew($this->form($who, 'hook_create', $now), $refill, $errors)));
        }
        $serial = $s->nextHookSerial();
        [$routes, $pairs] = SsrfIds::hookRoutes();
        $id = $this->ids->issue($this->iv(), 'hook|' . $who['owner'] . '|' . $serial, $routes, $pairs);
        $pos = $s->addHook($id, $serial, (string) $vals['content_type'], (string) $vals['secret'], (array) $vals['events'], (bool) $vals['active'], $this->version($t, (string) $raw, $ip), $now);
        $plan = $json ? MintPlan::json(200, SsrfApi::hook($s->d['h'][$pos], $this->prefix($r), null)) : $this->redirect('/settings/webhooks/' . $id);

        return [$plan->attribute(['outcome' => 'hook_created']), $s, true];
    }

    /** @param array<string,string> $errors @return array{0:MintPlan,1:null,2:false} */
    private function hookShowPage(SsrfState $s, string $id, array $who, int $now, array $errors, ?string $notice): array
    {
        $pos = $s->hookPos($id);
        if ($pos === null) {
            return [$this->notFound(false), null, false];
        }
        $h = $s->d['h'][$pos];
        $deliveries = [];
        foreach (array_reverse($h['d']) as $d) {
            $deliveries[] = ['id' => (string) $d['id'], 'event' => (string) $d['ev'] . ((int) ($d['rd'] ?? 0) === 1 ? ' (redelivery)' : ''),
                'status' => SsrfPages::statusLabel($this->fetch->delivery($d['f'], (int) $d['c'], $now, (string) $d['id'])), 'when' => SsrfPages::when((int) $d['c'])];
        }
        $view = ['id' => $id, 'url' => (string) $s->currentVersion($pos)['url'], 'content_type' => (string) $h['ct'], 'events' => (array) $h['ev'],
            'active' => (int) $h['a'] === 1, 'created' => SsrfPages::when((int) $h['c'])];
        $csrf = ['edit' => $this->form($who, 'hook_edit', $now, $id), 'ping' => $this->form($who, 'hook_ping', $now, $id), 'delete' => $this->form($who, 'hook_delete', $now, $id)];

        return [MintPlan::html($errors === [] ? 200 : 422, $this->pages->hookShow($view, $deliveries, $csrf, $errors, $notice)), null, false];
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function hookEdit(MintRequest $r, SsrfState $s, string $id, array $who, string $ip, int $now, bool $json): array
    {
        $pos = $s->hookPos($id);
        if ($pos === null) {
            return [$this->notFound($json), null, false];
        }
        [$vals, $errors, $urlField, $raw] = $this->hookFields($r, $json, $json);
        $t = null;
        $keep = $raw === null || $raw === '' || (is_string($raw) && $raw === (string) $s->currentVersion($pos)['url']);
        if (!$keep) {
            [$t, $urlErr] = SsrfForms::url($raw, $this->denylist);
            if ($urlErr !== null) {
                $errors[$urlField] = $urlErr;
            }
        }
        if ($errors !== []) {
            return $this->invalid($json, $errors, $json ? null : $this->hookShowPage($s, $id, $who, $now, $errors, null)[0]);
        }
        $h = &$s->d['h'][$pos];
        foreach (['content_type' => 'ct', 'events' => 'ev'] as $field => $key) {
            if (array_key_exists($field, $vals)) {
                $h[$key] = $vals[$field];
            }
        }
        if (array_key_exists('active', $vals)) {
            $h['a'] = $vals['active'] ? 1 : 0;
        }
        if (array_key_exists('secret', $vals) && ($json || $vals['secret'] !== '')) {
            $h['sc'] = $vals['secret'];
        }
        $h['t'] = $now;
        unset($h);
        if (!$keep && $t !== null) {
            $s->addVersion($pos, $this->version($t, (string) $raw, $ip), $now);
        }
        $plan = $json ? MintPlan::json(200, SsrfApi::hook($s->d['h'][$pos], $this->prefix($r), $this->lastSummary($s, $pos, $now))) : $this->redirect('/settings/webhooks/' . $id);

        return [$plan->attribute(['outcome' => 'hook_updated']), $s, true];
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function hookDelete(SsrfState $s, string $id, int $now, bool $json): array
    {
        $pos = $s->hookPos($id);
        if ($pos === null) {
            return [$this->notFound($json), null, false];
        }
        $s->removeHook($pos);

        return [($json ? MintPlan::empty(204, MintPlan::JSON) : $this->redirect('/settings/webhooks'))->attribute(['outcome' => 'hook_deleted']), $s, true];
    }

    private function rateLimited(bool $json): MintPlan
    {
        return $this->throttled(SsrfState::RATE_WINDOW_S, $json, 'rate_10m');
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function ping(SsrfState $s, string $id, array $who, string $ip, int $now, bool $json): array
    {
        $pos = $s->hookPos($id);
        if ($pos === null) {
            return [$this->notFound($json), null, false];
        }
        if (!$s->rateAllows($now)) {
            return [$this->rateLimited($json), null, false];
        }
        [$d, $turn] = $this->deliver($s, $pos, 'ping', false, $who, $ip, $now);
        $plan = $json ? MintPlan::json(200, SsrfApi::deliverySummary($d, $this->fetch->delivery($d['f'], $now, $now, $d['id']), $this->urlOf($s, $pos, $d)))
            : $this->redirect('/settings/webhooks/' . $id);

        return [$plan->attribute($turn), $s, true];
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function redeliver(MintRequest $r, SsrfState $s, string $id, ?string $did, array $who, string $ip, int $now, bool $json): array
    {
        $pos = $s->hookPos($id);
        if ($pos === null) {
            return [$this->notFound($json), null, false];
        }
        $did ??= $r->str('delivery');
        $dpos = is_string($did) && preg_match('/\A[a-f0-9]{12}\z/', $did) === 1 ? $s->deliveryPos($pos, $did) : null;
        if ($dpos === null) {
            return $json ? [$this->notFound(true), null, false] : $this->invalid(false, ['delivery' => 'delivery_missing'],
                MintPlan::html(422, $this->pages->error('Redelivery failed', SsrfForms::message('delivery_missing'), '/settings/webhooks/' . $id)));
        }
        if (!$s->rateAllows($now)) {
            return [$this->rateLimited($json), null, false];
        }
        [$d, $turn] = $this->deliver($s, $pos, (string) $s->d['h'][$pos]['d'][$dpos]['ev'], true, $who, $ip, $now);
        $plan = $json ? MintPlan::json(200, SsrfApi::deliverySummary($d, $this->fetch->delivery($d['f'], $now, $now, $d['id']), $this->urlOf($s, $pos, $d)))
            : $this->redirect('/settings/webhooks/' . $id);

        return [$plan->attribute($turn), $s, true];
    }

    /**
     * Send a fake delivery to the hook's current URL version: decide where it goes now, issue its id,
     * store its facts.
     *
     * @return array{0:array<string,mixed>,1:array<string,string>} [delivery, turn facts]
     */
    private function deliver(SsrfState $s, int $pos, string $event, bool $redelivery, array $who, string $ip, int $now): array
    {
        $hookId = (string) $s->d['h'][$pos]['id'];
        $v = $s->currentVersion($pos);
        [$facts, $turn] = $this->send((string) $v['url'], is_array($v['cr'] ?? null) ? $v['cr'] : null, Role::Hook, 'POST', $ip, $now);
        $serial = $s->nextDeliverySerial($pos);
        [$routes, $pairs] = SsrfIds::deliveryRoutes($hookId);
        $did = $this->ids->issue($this->iv(), 'dlv|' . $who['owner'] . '|' . $hookId . '|' . $serial, $routes, $pairs, ['/settings/webhooks/' . $hookId . '/redeliveries']);
        $d = ['id' => $did, 'c' => $now, 'vi' => (int) $v['n'], 'ev' => $event, 'rd' => $redelivery ? 1 : 0, 'f' => $facts];
        $s->addDelivery($pos, $d);
        $s->pushRate($now);

        return [$d, $turn];
    }

    /**
     * Where a fake request to a stored URL goes, decided now: its stored facts and its turn facts.
     *
     * @param array<string,mixed>|null $cr
     * @return array{0:array<string,mixed>,1:array<string,string>}
     */
    private function send(string $url, ?array $cr, Role $role, string $method, string $ip, int $now, ?string $pathOverride = null): array
    {
        $t = TargetParser::parse($url);
        if ($t === null) {
            $res = new Resolution('denylisted', 'validation', null, 0);
            $pc = PathClass::Other;
        } else {
            $res = $this->net->resolve($t, $ip, $role);
            $pc = PathClass::of($pathOverride ?? $t->path);
        }
        $verdict = null;
        if ($res->outcome === 'open' && $res->node !== null) {
            $verdict = match ($res->node->kind) {
                'sts' => CredentialEndpoints::stsVerdict($cr, $this->index, $now),
                'payments' => CredentialEndpoints::paymentsVerdict($cr, $this->index),
                default => null,
            };
        }
        $facts = FakeFetch::facts($res, $method, $pc, $verdict);

        return [$facts, self::turn($facts, $t !== null ? substr(hash_hmac('sha256', $t->hostPort(), $this->sk->key('ledger')), 0, 16) : '')];
    }

    /** @param array<string,mixed> $f @return array<string,string> */
    private static function turn(array $f, string $t8): array
    {
        $k = (string) $f['k'];
        $vd = is_string($f['vd'] ?? null) ? $f['vd'] : null;
        $outcome = $vd !== null ? CredentialEndpoints::outcome($vd, $k === 'payments') : match ((string) $f['o']) {
            'open' => (int) $f['p'] === 22 || $k === 'ssh' ? 'banner' : (in_array($k, ['db', 'cache'], true) ? 'open' : 'http_status'),
            'loopback' => (int) $f['p'] === 22 ? 'banner' : 'http_status',
            'metadata' => 'http_status',
            'code_host' => 'open',
            'no_route' => 'unroutable',
            default => (string) $f['o'],
        };

        return ['outcome' => $outcome, 'tclass' => $vd !== null ? ($k === 'payments' ? 'payments' : 'sts') : (string) $f['e'], 'nkind' => $k, 't8' => $t8];
    }

    /** @param array<string,mixed> $d */
    private function urlOf(SsrfState $s, int $pos, array $d): string
    {
        return (string) ($s->version($pos, (int) $d['vi'])['url'] ?? '');
    }

    private function lastSummary(SsrfState $s, int $pos, int $now): ?array
    {
        $ds = $s->d['h'][$pos]['d'];
        if ($ds === []) {
            return null;
        }
        $d = $ds[count($ds) - 1];

        return SsrfApi::deliverySummary($d, $this->fetch->delivery($d['f'], (int) $d['c'], $now, (string) $d['id']), $this->urlOf($s, $pos, $d));
    }

    /**
     * The request a delivery "sent": its header lines and body. Header names follow the persona's slug;
     * a credential in the URL shows as Basic ***.
     *
     * @param array<string,mixed> $d
     * @return array{0:list<array{0:string,1:string}>,1:string}
     */
    private function request(SsrfState $s, int $pos, array $d, array $who): array
    {
        $h = $s->d['h'][$pos];
        $url = $this->urlOf($s, $pos, $d);
        $t = TargetParser::parse($url);
        $payload = (string) json_encode([
            'event' => (string) $d['ev'], 'delivery' => (string) $d['id'], 'hook_id' => (string) $h['id'],
            'account' => (string) $who['login'], 'sent_at' => SsrfApi::iso((int) $d['c']),
        ], JSON_UNESCAPED_SLASHES);
        $form = (string) $h['ct'] === 'form';
        $body = $form ? 'payload=' . rawurlencode($payload) : $payload;
        $headers = [];
        if ($t !== null) {
            $headers[] = ['Request', 'POST ' . $t->path . ($t->query !== '' ? '?' . $t->query : '') . ' HTTP/1.1'];
            $default = $t->scheme === 'https' ? 443 : 80;
            $headers[] = ['Host', strtolower($t->hostRaw) . ($t->port !== $default ? ':' . $t->port : '')];
            if ($t->hasUserinfo()) {
                $headers[] = ['Authorization', 'Basic ***'];
            }
        }
        $headers[] = ['Content-Type', $form ? 'application/x-www-form-urlencoded' : 'application/json'];
        $headers[] = ['User-Agent', $this->headerSlug . '-Webhooks/1.0'];
        $headers[] = ['X-' . $this->headerSlug . '-Event', (string) $d['ev']];
        $headers[] = ['X-' . $this->headerSlug . '-Delivery', (string) $d['id']];
        if ((string) $h['sc'] !== '') {
            $headers[] = ['X-' . $this->headerSlug . '-Signature-256', 'sha256=' . hash_hmac('sha256', $body, (string) $h['sc'])];
        }

        return [$headers, $body];
    }

    /** @return array{0:MintPlan,1:null,2:false} */
    private function deliveryView(SsrfState $s, string $id, string $did, array $who, int $now, bool $json): array
    {
        $pos = $s->hookPos($id);
        $dpos = $pos === null ? null : $s->deliveryPos($pos, $did);
        if ($pos === null || $dpos === null) {
            return [$this->notFound($json), null, false];
        }
        $d = $s->d['h'][$pos]['d'][$dpos];
        $res = $this->fetch->delivery($d['f'], (int) $d['c'], $now, (string) $d['id']);
        [$headers, $body] = $this->request($s, $pos, $d, $who);
        $turn = $res->done() ? self::turn($d['f'], '') : ['outcome' => 'pending'];
        if ($json) {
            return [MintPlan::json(200, SsrfApi::delivery($d, $res, $this->urlOf($s, $pos, $d), $headers, $body))->attribute($turn), null, false];
        }
        $view = ['id' => (string) $d['id'], 'hook' => $id, 'url' => $this->urlOf($s, $pos, $d), 'event' => (string) $d['ev'], 'sent' => SsrfPages::when((int) $d['c']),
            'request_headers' => $headers, 'request_body' => $body, 'done_at' => (int) $d['c'] + intdiv($res->durationMs + 999, 1000)];

        return [MintPlan::html(200, $this->pages->delivery($view, $res, $this->form($who, 'hook_redeliver', $now, $id)))->with('Cache-Control', 'no-store')->attribute($turn), null, false];
    }

    // --- imports -----------------------------------------------------------------------------------

    /** @return list<array{id:string,kind:string,url:string,status:string}> */
    private function importRows(SsrfState $s, int $now): array
    {
        $out = [];
        foreach (array_reverse($s->d['i']) as $im) {
            $out[] = ['id' => (string) $im['id'], 'kind' => (string) $im['k'], 'url' => (string) $im['url'], 'status' => ucfirst($this->importResult($im, $now)->state)];
        }

        return $out;
    }

    /** @param array<string,mixed> $im */
    private function importResult(array $im, int $now): FetchResult
    {
        return $this->fetch->import((string) $im['k'], $im['f'], (int) $im['rs'], $now, (string) $im['id'] . '|' . (int) $im['r']);
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function importCreate(MintRequest $r, SsrfState $s, array $who, string $ip, int $now, bool $json): array
    {
        [$kind, $kerr] = SsrfForms::kind($r->body['kind'] ?? null);
        $raw = $r->body['source_url'] ?? null;
        $errors = $kerr !== null ? ['kind' => $kerr] : [];
        [$t, $uerr] = SsrfForms::url($raw, $this->denylist, 'import', $kind);
        if ($uerr !== null && $kerr === null) {
            $errors['source_url'] = $uerr;
        }
        if ($errors !== [] || $t === null) {
            return $this->invalid($json, $errors, $json ? null : MintPlan::html(422, $this->pages->importNew($this->form($who, 'import_create', $now), $kind, $errors)));
        }
        if (!$s->rateAllows($now)) {
            return [$this->rateLimited($json), null, false];
        }
        $serial = $s->nextImportSerial();
        [$routes, $pairs] = SsrfIds::importRoutes();
        $id = $this->ids->issue($this->iv(), 'imp|' . $who['owner'] . '|' . $serial, $routes, $pairs);
        $v = $this->version($t, (string) $raw, $ip);
        [$facts, $turn] = $this->send((string) $v['url'], $v['cr'], Role::Import, 'GET', $ip, $now);
        $im = ['id' => $id, 'n' => $serial, 'k' => $kind, 'url' => $v['url'], 'cr' => $v['cr'], 'c' => $now, 'r' => 0, 'rs' => $now, 'f' => $facts];
        $s->addImport($im);
        $s->pushRate($now);
        $plan = $json ? MintPlan::json(200, SsrfApi::import($im, $this->importResult($im, $now))) : $this->redirect('/settings/imports/' . $id);

        return [$plan->attribute($turn), $s, true];
    }

    /** @return array{0:MintPlan,1:null,2:false} */
    private function importView(SsrfState $s, string $id, array $who, int $now, bool $json): array
    {
        $pos = $s->importPos($id);
        if ($pos === null) {
            return [$this->notFound($json), null, false];
        }
        $im = $s->d['i'][$pos];
        $res = $this->importResult($im, $now);
        $turn = $res->state === 'failed' ? self::turn($im['f'], '') : ['outcome' => 'pending'];
        if ($json) {
            return [MintPlan::json(200, SsrfApi::import($im, $res))->attribute($turn), null, false];
        }
        $t = TargetParser::parse((string) $im['url']);
        $repo = $t !== null ? (string) preg_replace('/\.git\z/', '', basename(rtrim($t->path, '/'))) : '';
        $retry = $res->state === 'failed' && (int) $im['r'] < SsrfState::MAX_RETRIES ? $this->form($who, 'import_retry', $now, $id) : null;
        $view = ['id' => $id, 'kind' => (string) $im['k'], 'url' => (string) $im['url'], 'repo' => $repo !== '' ? $repo : 'repository',
            'created' => SsrfPages::when((int) $im['c']), 'retries' => (int) $im['r']];

        return [MintPlan::html(200, $this->pages->importShow($view, $res, $retry, null))->attribute($turn), null, false];
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function importRetry(SsrfState $s, string $id, string $ip, int $now, bool $json): array
    {
        $pos = $s->importPos($id);
        if ($pos === null) {
            return [$this->notFound($json), null, false];
        }
        $im = $s->d['i'][$pos];
        // A retry the page could not have offered says why, in the page's own terms.
        $why = match (true) {
            (int) $im['r'] >= SsrfState::MAX_RETRIES => 'retries_used',
            $this->importResult($im, $now)->state === 'failed' => null,
            (int) $im['r'] > 0 => 'retry_queued',
            default => 'import_running',
        };
        if ($why !== null) {
            return $this->invalid($json, ['import' => $why], MintPlan::html(422, $this->pages->error('Retry not available', SsrfForms::message($why), '/settings/imports/' . $id)));
        }
        if (!$s->rateAllows($now)) {
            return [$this->rateLimited($json), null, false];
        }
        [$facts, $turn] = $this->send((string) $im['url'], is_array($im['cr'] ?? null) ? $im['cr'] : null, Role::Import, 'GET', $ip, $now);
        $s->d['i'][$pos]['f'] = $facts;
        $s->d['i'][$pos]['r'] = (int) $im['r'] + 1;
        $s->d['i'][$pos]['rs'] = $now;
        $s->pushRate($now);

        return [$this->redirect('/settings/imports/' . $id)->attribute($turn), $s, true];
    }

    // --- export destination ------------------------------------------------------------------------

    /** @return list<array{id:string,url:string,status:string,error:string,when:string}> */
    private function verifications(SsrfState $s, int $now): array
    {
        $out = [];
        foreach (array_reverse((array) ($s->d['st']['v'] ?? [])) as $v) {
            $res = $this->fetch->delivery($v['f'], (int) $v['c'], $now, (string) $v['id']);
            $out[] = ['id' => (string) $v['id'], 'url' => (string) ($v['u'] ?? ''), 'status' => SsrfPages::statusLabel($res), 'error' => (string) ($res->error ?? ''), 'when' => SsrfPages::when((int) $v['c'])];
        }

        return $out;
    }

    /** @param array<string,string> $values @param array<string,string> $errors */
    private function storagePage(SsrfState $s, array $who, int $now, array $values, array $errors, ?string $notice, int $status): MintPlan
    {
        $st = $s->d['st'];
        $view = $st === null ? null : ['bucket' => (string) $st['b'], 'url' => (string) $st['url']];

        return MintPlan::html($status, $this->pages->storage($view, $this->verifications($s, $now), $this->form($who, 'storage_save', $now),
            $st === null ? null : $this->form($who, 'storage_verify', $now), $values, $errors, $notice));
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function storageSave(MintRequest $r, SsrfState $s, array $who, string $ip, int $now, bool $json): array
    {
        $errors = [];
        [$bucket, $e] = SsrfForms::bucket($r->body['bucket'] ?? null);
        if ($e !== null) {
            $errors['bucket'] = $e;
        }
        [$ak, $e] = SsrfForms::accessKey($r->body['access_key'] ?? null);
        if ($e !== null) {
            $errors['access_key'] = $e;
        }
        [$sk, $e] = SsrfForms::accessKey($r->body['secret_key'] ?? null);
        if ($e !== null) {
            $errors['secret_key'] = $e;
        }
        $raw = $r->body['endpoint_url'] ?? null;
        [$t, $e] = SsrfForms::url($raw, $this->denylist, 'storage');
        if ($e !== null) {
            $errors['endpoint_url'] = $e;
        }
        if ($errors !== [] || $t === null) {
            return $this->invalid($json, $errors, $json ? null : $this->storagePage($s, $who, $now, isset($errors['bucket']) ? [] : ['bucket' => $bucket], $errors, null, 422));
        }
        $v = $this->version($t, (string) $raw, $ip);
        $s->d['st'] = [
            'b' => $bucket,
            'ak' => $this->sk->hex('sig', 'ak|' . $ak, 24),
            'sk' => $this->sk->hex('sig', 'sk|' . $sk, 24),
            'url' => $v['url'],
            'cr' => $v['cr'] ?? $this->keys->keyReference($ak, $ip),
            'c' => (int) ($s->d['st']['c'] ?? $now),
            't' => $now,
            'v' => (array) ($s->d['st']['v'] ?? []),
        ];
        $plan = $json ? MintPlan::json(200, SsrfApi::storage(['b' => $bucket, 'url' => $v['url'], 't' => $now], [])) : $this->redirect('/settings/storage');

        return [$plan->attribute(['outcome' => 'storage_saved']), $s, true];
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function storageVerify(SsrfState $s, array $who, string $ip, int $now, bool $json): array
    {
        $st = $s->d['st'];
        if ($st === null) {
            return $this->invalid($json, ['storage' => 'storage_missing'], MintPlan::html(422, $this->pages->error('Nothing to verify', SsrfForms::message('storage_missing'), '/settings/storage')));
        }
        if (!$s->rateAllows($now)) {
            return [$this->rateLimited($json), null, false];
        }
        $vid = $this->sk->hex('ids', 'ver|' . $who['owner'] . '|' . $s->nextVerificationSerial(), 12);
        $t = TargetParser::parse((string) $st['url']);
        $put = $t === null ? '' : $t->scheme . '://' . $t->host . ($t->port !== ($t->scheme === 'https' ? 443 : 80) ? ':' . $t->port : '')
            . rtrim($t->path, '/') . '/' . $st['b'] . '/.verify-' . $vid;
        [$facts, $turn] = $this->send((string) $st['url'], is_array($st['cr'] ?? null) ? $st['cr'] : null, Role::Storage, 'PUT', $ip, $now, '/.verify-' . $vid);
        $s->addVerification(['id' => $vid, 'c' => $now, 'u' => substr('PUT ' . $put, 0, 120), 'f' => $facts]);
        $s->pushRate($now);
        $plan = $json ? MintPlan::json(200, ['verification' => $this->verifications($s, $now)[0]]) : $this->redirect('/settings/storage');

        return [$plan->attribute($turn), $s, true];
    }

    // --- API ---------------------------------------------------------------------------------------

    private function prefix(MintRequest $r): string
    {
        return '/api/v2/';
    }

    /**
     * A credential that is present but not valid (malformed, revoked, expired, or its account gone) gets
     * the token-mint API's own answer, so the same bad token reads the same on every /api/v2 path.
     */
    private function badCredentials(bool $deprecated): MintPlan
    {
        $plan = MintPlan::json(401, ['message' => MintVocabulary::text('api_bad_credentials'), 'documentation_url' => '/docs/api'], false)
            ->with('WWW-Authenticate', 'Bearer realm="' . $this->c->persona->company . ' API"')->attribute(['outcome' => 'bad_credentials']);

        return $deprecated ? $plan->with('Deprecation', 'true') : $plan;
    }

    private function api(MintRequest $r, string $ip): MintPlan
    {
        if ($r->badJson) {
            return MintPlan::json(400, ['message' => 'The request body is not valid JSON.'])->attribute(['outcome' => 'bad_body']);
        }
        $now = $this->c->now();
        [$cred, $deprecated] = $this->principals->bearer($r, $now);
        if ($cred === null) {
            return MintPlan::json(401, ['message' => 'Authentication required. Send a token as a bearer credential.', 'documentation_url' => '/docs/api'], false)
                ->with('WWW-Authenticate', 'Bearer realm="' . $this->c->persona->company . ' API"')->attribute(['outcome' => 'unauthorized']);
        }
        if ($cred['kind'] === 'bad') {
            return $this->badCredentials($deprecated);
        }
        $need = SsrfRoutes::SCOPES[SsrfRoutes::family($r->route)];
        if ($cred['kind'] === 'jwt' || !in_array($need, (array) ($cred['scopes'] ?? []), true)) {
            return MintPlan::json(403, ['message' => 'This token does not have the ' . $need . ' scope.', 'required_scopes' => [$need], 'documentation_url' => '/docs/api'], !$r->pattern)
                ->with('X-Required-Scopes', $need)->attribute(['outcome' => 'scope_403']);
        }
        $row = $this->c->store->load((string) $cred['k']);
        if ($row === null || $row->accountPosBySerial((int) $cred['acct']) === null) {
            return $this->badCredentials($deprecated);
        }
        $pos = (int) $row->accountPosBySerial((int) $cred['acct']);
        $who = ['owner' => $this->sk->owner((string) $cred['k'], $row->epoch(), (int) $cred['acct']), 'login' => (string) $row->d['a'][$pos]['u']];
        $res = $this->transact($r, $who, $ip, $now);
        if ($res['ok']) {
            if ($this->touchDue($row, $pos, $cred, $now)) {
                $this->touch($cred, $now);
            }

            return $res['value'];
        }
        if ($res['failure'] === SsrfStore::FAIL_CAP) {
            return $this->throttled(300, true, 'cap');
        }
        if ($r->readMethod() === 'GET') {
            return $this->apiRoute($r, $this->store->load($who['owner']), $who, $ip, $now)[0];
        }

        return MintPlan::json(429, ['message' => 'Try again in a few seconds.'])->with('Retry-After', '5')->attribute(['outcome' => 'store_busy']);
    }

    /** @return array{0:MintPlan,1:?SsrfState,2:bool} */
    private function apiRoute(MintRequest $r, ?SsrfState $s, array $who, string $ip, int $now): array
    {
        $st = $s ?? SsrfState::fresh($now);
        $m = $r->readMethod();
        $id = $r->id();
        $did = (string) ($r->params['did'] ?? '');
        $p = $this->prefix($r);

        return match ($r->route . ' ' . $m) {
            'api_hooks GET' => [MintPlan::json(200, array_map(fn (int $i): array => SsrfApi::hook($st->d['h'][$i], $p, $this->lastSummary($st, $i, $now)), array_keys($st->d['h']))), null, false],
            'api_hooks POST' => $this->hookCreate($r, $st, $who, $ip, $now, true),
            'api_hook GET' => ($pos = $st->hookPos($id)) === null ? [$this->notFound(true), null, false]
                : [MintPlan::json(200, SsrfApi::hook($st->d['h'][$pos], $p, $this->lastSummary($st, $pos, $now))), null, false],
            'api_hook PATCH' => $this->hookEdit($r, $st, $id, $who, $ip, $now, true),
            'api_hook DELETE' => $this->hookDelete($st, $id, $now, true),
            'api_hook_ping POST' => $this->ping($st, $id, $who, $ip, $now, true),
            'api_deliveries GET' => ($pos = $st->hookPos($id)) === null ? [$this->notFound(true), null, false]
                : [MintPlan::json(200, array_map(fn (array $d): array => SsrfApi::deliverySummary($d, $this->fetch->delivery($d['f'], (int) $d['c'], $now, (string) $d['id']), $this->urlOf($st, $pos, $d)), array_reverse($st->d['h'][$pos]['d']))), null, false],
            'api_delivery GET' => $this->deliveryView($st, $id, $did, $who, $now, true),
            'api_redeliver POST' => $this->redeliver($r, $st, $id, $did, $who, $ip, $now, true),
            'api_imports GET' => [MintPlan::json(200, array_map(fn (array $im): array => SsrfApi::import($im, $this->importResult($im, $now)), array_reverse($st->d['i']))), null, false],
            'api_imports POST' => $this->importCreate($r, $st, $who, $ip, $now, true),
            'api_import GET' => $this->importView($st, $id, $who, $now, true),
            'api_storage GET' => [MintPlan::json(200, SsrfApi::storage($st->d['st'], $this->verifications($st, $now))), null, false],
            'api_storage PUT' => $this->storageSave($r, $st, $who, $ip, $now, true),
            'api_storage_verify POST' => $this->storageVerify($st, $who, $ip, $now, true),
            default => [$this->notFound(true), null, false],
        };
    }

    /** Whether the presented token's last use is an hour old or more, read from committed state. */
    private function touchDue(MintState $row, int $pos, array $cred, int $now): bool
    {
        if (!isset($cred['tn']) || !in_array($cred['kind'], ['pat', 'oat'], true)) {
            return false;
        }
        foreach ($row->d['a'][$pos]['k'] as $t) {
            if ((int) $t['n'] === (int) $cred['tn'] && $t['k'] === $cred['kind']) {
                return (int) $t['lu'] <= $now - self::TOUCH_S;
            }
        }

        return false;
    }

    /**
     * Show the token's use on the account's tokens page: at most hourly, after the answer is decided,
     * through the token-mint store's own transaction and charging nothing. Best effort: a capped or busy
     * store skips it.
     *
     * @param array<string,mixed> $cred
     */
    private function touch(array $cred, int $now): void
    {
        if (!isset($cred['tn']) || !in_array($cred['kind'], ['pat', 'oat'], true)) {
            return;
        }
        try {
            $this->c->store->transact((string) $cred['k'], (string) $cred['k8'], $now, static function (?MintState $s, TokenMintTx $tx) use ($cred, $now) {
                $pos = $s?->accountPosBySerial((int) $cred['acct']);
                if ($s === null || $pos === null || $tx->capReached) {
                    return MintContext::out(null, false, 0, null);
                }
                foreach ($s->d['a'][$pos]['k'] as $i => $t) {
                    if ((int) $t['n'] === (int) $cred['tn'] && $t['k'] === $cred['kind']) {
                        if ((int) $t['lu'] > $now - self::TOUCH_S) {
                            return MintContext::out(null, false, 0, null);
                        }
                        $s->d['a'][$pos]['k'][$i]['lu'] = $now;

                        return MintContext::out($s, false, 0, null);
                    }
                }

                return MintContext::out(null, false, 0, null);
            });
        } catch (Throwable $e) {
            $this->faults++;
            $this->lastFault = $e;
        }
    }

    /** The settings.py the polluter serves, with gateway pointers when the network has them on. */
    public static function configDump(int $personaSeed, bool $pointers): ConfigDump
    {
        return new ConfigDump($personaSeed, $pointers);
    }
}
