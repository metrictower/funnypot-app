<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\AccountPages;

/**
 * The webhook, import and export-destination pages, in the account surface's chrome. Every dynamic
 * value is escaped; stored URLs are shown as text, never as a link or a source; every form posts to
 * an owned path with its URL field last. Nothing from a GET query, a path or a header is ever passed in.
 */
final class SsrfPages
{
    private const REASONS = [
        200 => 'OK', 204 => 'No Content', 400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden', 404 => 'Not Found',
        405 => 'Method Not Allowed', 415 => 'Unsupported Media Type', 429 => 'Too Many Requests',
    ];

    public function __construct(private AccountPages $chrome, private string $company)
    {
    }

    public static function e(string $s): string
    {
        return AccountPages::e($s);
    }

    private static function csrf(string $token): string
    {
        return "<input type=hidden name=csrf_token value='" . self::e($token) . "'>";
    }

    private static function err(array $errors, string $field): string
    {
        return isset($errors[$field]) ? '<p class=err>' . self::e(SsrfForms::message($errors[$field])) . '</p>' : '';
    }

    public static function when(int $ts): string
    {
        return gmdate('Y-m-d H:i:s', $ts) . ' UTC';
    }

    private function page(string $title, string $main, ?string $notice = null): string
    {
        return $this->chrome->layout($title, $main, true, $notice);
    }

    public static function statusLabel(FetchResult $r): string
    {
        return match ($r->state) {
            'pending' => 'Pending',
            'retrying' => 'Retrying',
            'delivered' => (string) ($r->reply?->status ?? 200) . ' delivered',
            default => $r->reply?->ok() ? $r->reply->status . ' failed' : 'Failed',
        };
    }

    // --- webhooks ----------------------------------------------------------------------------------

    /** @param list<array{id:string,url:string,active:bool,last:string}> $hooks */
    public function hooks(array $hooks, ?string $notice): string
    {
        $rows = '';
        foreach ($hooks as $h) {
            $rows .= "<tr><td><a href='/settings/webhooks/" . self::e($h['id']) . "'>" . self::e($h['id']) . '</a></td>'
                . '<td class=mono>' . self::e($h['url']) . '</td><td>' . ($h['active'] ? 'Active' : 'Inactive') . '</td><td>' . self::e($h['last']) . '</td></tr>';
        }
        $main = '<div class=card><h1>Webhooks</h1><p class=muted>Webhooks send a POST request to your URL when events happen in your account. '
            . 'Deliveries are made by the platform\'s delivery workers and retried on timeouts.</p>'
            . "<p><a href='/settings/webhooks/new'>Add webhook</a></p>"
            . ($rows === '' ? '<p class=muted>No webhooks yet.</p>' : '<table><tr><th>Webhook</th><th>Payload URL</th><th>State</th><th>Last delivery</th></tr>' . $rows . '</table>') . '</div>';

        return $this->page('Webhooks', $main, $notice);
    }

    /**
     * The add and edit forms: form token first, payload URL last. On edit the URL field is blank, so a
     * stored URL is never re-sent; blank keeps the current one.
     *
     * @param array<string,mixed> $values
     * @param array<string,string> $errors
     */
    private function hookForm(string $action, string $csrf, array $values, array $errors, bool $edit): string
    {
        $ct = (string) ($values['content_type'] ?? 'json');
        $events = (array) ($values['events'] ?? [SsrfForms::DEFAULT_EVENT]);
        $active = (bool) ($values['active'] ?? true);
        $opts = '';
        foreach (SsrfForms::CONTENT_TYPES as $c) {
            $opts .= "<option value='{$c}'" . ($ct === $c ? ' selected' : '') . '>' . SsrfForms::CONTENT_TYPE_LABELS[$c] . '</option>';
        }
        $boxes = '';
        foreach (SsrfForms::EVENTS as $ev => $label) {
            $boxes .= "<label class=scope><input type=checkbox name='events[]' value='{$ev}'" . (in_array($ev, $events, true) ? ' checked' : '') . '>' . self::e($label) . '</label>';
        }

        return "<form method=post action='" . self::e($action) . "'>" . self::csrf($csrf)
            . "<label>Content type<select name=content_type>{$opts}</select></label>" . self::err($errors, 'content_type')
            . "<label>Secret<input type=password name=secret value='' autocomplete=off></label><p class=muted>Used to sign each delivery (HMAC-SHA256).</p>" . self::err($errors, 'secret')
            . '<h2>Events</h2>' . $boxes . self::err($errors, 'events')
            . "<input type=hidden name=active value='0'><label class=scope><input type=checkbox name=active value='1'" . ($active ? ' checked' : '') . '>Active</label>'
            . "<label>Payload URL<input type=url name=payload_url value='' autocomplete=off></label>"
            . ($edit ? '<p class=muted>Leave blank to keep the current URL. Credentials in a URL are never shown.</p>' : '')
            . self::err($errors, 'payload_url') . self::err($errors, 'hook')
            . '<button type=submit>' . ($edit ? 'Update webhook' : 'Add webhook') . '</button></form>';
    }

    /** @param array<string,mixed> $values @param array<string,string> $errors */
    public function hookNew(string $csrf, array $values, array $errors): string
    {
        return $this->page('Add webhook', '<div class=card><h1>Add webhook</h1>' . $this->hookForm('/settings/webhooks', $csrf, $values, $errors, false) . '</div>');
    }

    /**
     * @param array<string,mixed> $hook id, url, content_type, events, active, created
     * @param list<array{id:string,event:string,status:string,when:string}> $deliveries
     * @param array{edit:string,ping:string,delete:string} $csrf
     * @param array<string,string> $errors
     */
    public function hookShow(array $hook, array $deliveries, array $csrf, array $errors, ?string $notice): string
    {
        $id = (string) $hook['id'];
        $rows = '';
        foreach ($deliveries as $d) {
            $rows .= "<tr><td class=mono><a href='/settings/webhooks/" . self::e($id) . '/deliveries/' . self::e($d['id']) . "'>" . self::e($d['id']) . '</a></td>'
                . '<td>' . self::e($d['event']) . '</td><td>' . self::e($d['status']) . '</td><td>' . self::e($d['when']) . '</td></tr>';
        }
        $main = '<div class=card><h1>Webhook ' . self::e($id) . '</h1>'
            . '<p>Payload URL: <span class=mono>' . self::e((string) $hook['url']) . '</span></p>'
            . '<p class=muted>Content type: ' . self::e((string) $hook['content_type']) . ' · Events: ' . self::e(implode(', ', (array) $hook['events']))
            . ' · ' . ($hook['active'] ? 'Active' : 'Inactive') . ' · Created ' . self::e((string) $hook['created']) . '</p>'
            . "<form method=post action='/settings/webhooks/" . self::e($id) . "/pings'>" . self::csrf($csrf['ping'])
            . '<button type=submit>Send test delivery</button></form></div>'
            . '<div class=card><h2>Recent deliveries</h2>'
            . ($rows === '' ? '<p class=muted>No deliveries yet.</p>' : '<table><tr><th>Delivery</th><th>Event</th><th>Status</th><th>Sent</th></tr>' . $rows . '</table>')
            . '<p class=muted>The ten most recent deliveries are kept. Deliveries to a URL older than the last three are removed.</p></div>'
            . '<div class=card><h2>Edit</h2>' . $this->hookForm('/settings/webhooks/' . $id, $csrf['edit'], $hook, $errors, true) . '</div>'
            . "<div class=card><h2>Delete webhook</h2><form method=post action='/settings/webhooks/" . self::e($id) . "/delete'>" . self::csrf($csrf['delete'])
            . '<button class=danger type=submit>Delete webhook</button></form></div>';

        return $this->page('Webhook', $main, $notice);
    }

    /**
     * @param array<string,mixed> $d id, hook, url, event, sent, request headers and body, result
     */
    public function delivery(array $d, FetchResult $r, string $csrf): string
    {
        $hook = (string) $d['hook'];
        $req = '';
        foreach ($d['request_headers'] as [$n, $v]) {
            $req .= self::e($n . ': ' . $v) . "\n";
        }
        $resp = 'No response.';
        if ($r->reply !== null && $r->reply->ok()) {
            $status = (int) $r->reply->status;
            $resp = self::e('HTTP/1.1 ' . $status . ' ' . (self::REASONS[$status] ?? '')) . "\n"
                . ($r->reply->contentType !== '' ? self::e('Content-Type: ' . $r->reply->contentType) . "\n" : '')
                . self::e('Content-Length: ' . strlen($r->reply->body)) . "\n" . self::e('Date: ' . gmdate('D, d M Y H:i:s', (int) $d['done_at']) . ' GMT') . "\n\n"
                . self::e($r->reply->body);
        } elseif ($r->reply !== null && $r->reply->body !== '') {
            $resp = self::e($r->reply->body);
        }
        $attempts = '';
        foreach ($r->attempts as $a) {
            $attempts .= '<tr><td>' . self::e(self::when($a['at'])) . '</td><td>' . self::e(strtr($a['state'], ['_' => ' '])) . '</td><td>'
                . ($a['ms'] > 0 ? $a['ms'] . ' ms' : '') . '</td><td>' . self::e((string) ($a['error'] ?? '')) . '</td></tr>';
        }
        $main = '<div class=card><h1>Delivery ' . self::e((string) $d['id']) . '</h1>'
            . '<p class=muted>' . self::e((string) $d['event']) . ' event · sent ' . self::e((string) $d['sent']) . ' · ' . self::e(self::statusLabel($r))
            . ($r->durationMs > 0 ? ' in ' . $r->durationMs . ' ms' : '') . '</p>'
            . '<p>Sent to: <span class=mono>' . self::e((string) $d['url']) . '</span></p>'
            . ($r->error !== null ? '<p class=err>' . self::e($r->error) . '</p>' : '')
            . "<form method=post action='/settings/webhooks/" . self::e($hook) . "/redeliveries'>" . self::csrf($csrf)
            . "<input type=hidden name=delivery value='" . self::e((string) $d['id']) . "'><button type=submit>Redeliver</button></form>"
            . '<p class=muted>A redelivery sends the same event to the webhook\'s current URL.</p></div>'
            . '<div class=card><h2>Request</h2><pre class=mono>' . $req . "\n" . self::e((string) $d['request_body']) . '</pre></div>'
            . '<div class=card><h2>Response</h2><pre class=mono>' . $resp . '</pre></div>'
            . ($attempts !== '' ? '<div class=card><h2>Attempts</h2><table>' . $attempts . '</table></div>' : '');

        return $this->page('Delivery', $main);
    }

    // --- imports -----------------------------------------------------------------------------------

    /** @param list<array{id:string,kind:string,url:string,status:string}> $imports */
    public function imports(array $imports, ?string $notice): string
    {
        $rows = '';
        foreach ($imports as $i) {
            $rows .= "<tr><td><a href='/settings/imports/" . self::e($i['id']) . "'>" . self::e($i['id']) . '</a></td><td>' . self::e(SsrfForms::KINDS[$i['kind']] ?? $i['kind'])
                . '</td><td class=mono>' . self::e($i['url']) . '</td><td>' . self::e($i['status']) . '</td></tr>';
        }
        $main = '<div class=card><h1>Imports</h1><p class=muted>Import orders or mirror a repository into your personal sandbox. '
            . 'Imports run on the platform\'s import workers.</p>'
            . "<p><a href='/settings/imports/new'>New import</a></p>"
            . ($rows === '' ? '<p class=muted>No imports yet.</p>' : '<table><tr><th>Import</th><th>Kind</th><th>Source</th><th>Status</th></tr>' . $rows . '</table>') . '</div>';

        return $this->page('Imports', $main, $notice);
    }

    /** @param array<string,string> $errors */
    public function importNew(string $csrf, string $kind, array $errors): string
    {
        $opts = '';
        foreach (SsrfForms::KINDS as $k => $label) {
            $opts .= "<option value='{$k}'" . ($kind === $k ? ' selected' : '') . '>' . self::e($label) . '</option>';
        }
        $main = "<div class=card><h1>New import</h1><form method=post action='/settings/imports'>" . self::csrf($csrf)
            . "<label>Kind<select name=kind>{$opts}</select></label>" . self::err($errors, 'kind')
            . "<label>Source URL<input type=url name=source_url value='' autocomplete=off></label>" . self::err($errors, 'source_url')
            . '<p class=muted>Orders imports read a CSV or JSON file with an order_id column. Mirrors copy a Git repository.</p>'
            . '<button type=submit>Start import</button></form></div>';

        return $this->page('New import', $main);
    }

    /** @param array<string,mixed> $im id, kind, url, repo, created, retries @param string|null $csrf the retry form, when a retry is open */
    public function importShow(array $im, FetchResult $r, ?string $csrf, ?string $notice): string
    {
        $stage = match ($r->state) {
            'queued' => 'Queued',
            'fetching' => 'Fetching the source',
            'waiting' => 'Waiting for an import worker',
            'cloning' => "Cloning into '" . (string) $im['repo'] . "'…",
            default => 'Failed: ' . (string) $r->error,
        };
        $excerpt = $r->reply !== null && $r->state === 'failed' ? substr($r->reply->body, 0, 512) : '';
        $main = '<div class=card><h1>Import ' . self::e((string) $im['id']) . '</h1>'
            . '<p class=muted>' . self::e(SsrfForms::KINDS[(string) $im['kind']] ?? '') . ' · started ' . self::e((string) $im['created'])
            . ' · retries ' . (int) $im['retries'] . ' of ' . SsrfState::MAX_RETRIES . '</p>'
            . '<p>Source: <span class=mono>' . self::e((string) $im['url']) . '</span></p>'
            . '<p' . ($r->state === 'failed' ? ' class=err' : '') . '>' . self::e($stage) . '</p>'
            . ($excerpt !== '' ? '<h2>Response excerpt</h2><pre class=mono>' . self::e($excerpt) . '</pre>' : '')
            . ($csrf !== null ? "<form method=post action='/settings/imports/" . self::e((string) $im['id']) . "/retry'>" . self::csrf($csrf)
                . '<button type=submit>Retry import</button></form>' : '')
            . '</div>';

        return $this->page('Import', $main, $notice);
    }

    // --- export destination ------------------------------------------------------------------------

    /**
     * @param array<string,mixed>|null $st bucket, url, configured
     * @param list<array{id:string,url:string,status:string,error:string,when:string}> $verifications
     * @param array<string,string> $values
     * @param array<string,string> $errors
     */
    public function storage(?array $st, array $verifications, string $csrfSave, ?string $csrfVerify, array $values, array $errors, ?string $notice): string
    {
        $bucket = (string) ($values['bucket'] ?? ($st['bucket'] ?? ''));
        $rows = '';
        foreach ($verifications as $v) {
            $rows .= '<tr><td class=mono>' . self::e($v['url']) . '</td><td>' . self::e($v['status']) . '</td><td>' . self::e($v['error']) . '</td><td>' . self::e($v['when']) . '</td></tr>';
        }
        $main = '<div class=card><h1>Export destination</h1><p class=muted>Order exports are written to an S3-compatible bucket you control. '
            . 'Uploads use path-style requests from the platform\'s export workers.</p>'
            . ($st !== null ? '<p>Current endpoint: <span class=mono>' . self::e((string) $st['url']) . '</span> · bucket <span class=mono>' . self::e((string) $st['bucket']) . '</span></p>' : '')
            . "<form method=post action='/settings/storage'>" . self::csrf($csrfSave)
            . "<label>Bucket<input name=bucket value='" . self::e($bucket) . "' autocomplete=off></label>" . self::err($errors, 'bucket')
            . "<label>Access key<input name=access_key value='' autocomplete=off></label>" . self::err($errors, 'access_key')
            . "<label>Secret key<input type=password name=secret_key value='' autocomplete=off></label>" . self::err($errors, 'secret_key')
            . "<label>Endpoint URL<input type=url name=endpoint_url value='' autocomplete=off></label>" . self::err($errors, 'endpoint_url')
            . '<button type=submit>Save destination</button></form></div>'
            . ($csrfVerify !== null ? "<div class=card><h2>Verify connection</h2><form method=post action='/settings/storage/verify'>" . self::csrf($csrfVerify)
                . '<p class=muted>Uploads a small test object and reports what the endpoint answered.</p><button type=submit>Verify connection</button></form>'
                . ($rows !== '' ? '<table><tr><th>Request</th><th>Result</th><th>Error</th><th>When</th></tr>' . $rows . '</table>' : '') . '</div>' : '');

        return $this->page('Export destination', $main, $notice);
    }

    /** A form-level answer: an expired form, a save failure, a throttle. */
    public function error(string $title, string $message, string $back): string
    {
        return $this->chrome->error($title, $message, $back, 'Go back', true);
    }

    public function notFound(): string
    {
        return $this->chrome->notFound(true);
    }
}
