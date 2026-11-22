<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * What a host on the fake network answers. Every answer is a pure function of the node's key and kind,
 * the port, the method, the path class and, for the credential gateways, the verdict, so no byte of a
 * request can reach a rendered body. Error texts never name the host.
 *
 * Index pages of API services and registries list 6 to 12 neighbours, so the network has no edge: a
 * fixed share of each listing names hosts other surfaces leaked (settings.py, the fleet, the wiki), the
 * rest are generated hosts. Metrics pages carry upstream labels in an application exporter's style, with
 * no runtime series.
 */
final class NodeAnswers
{
    /** The fetch worker's own loopback ports that answer; every other loopback port refuses. */
    public const LOOPBACK_PORTS = [22, 6379, 8080, 9090];

    public const PROXY_DENIED = 'Request denied by egress policy: destination is not on the allowlist.';

    private const BANNERS = [
        'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3',
        'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
        'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5',
    ];

    public function __construct(private Network $net, private string $company)
    {
    }

    /** The outcome's error text, as a fetch worker logs it; null for an answer that has a reply. */
    public static function error(string $outcome): ?string
    {
        return match ($outcome) {
            'nxdomain' => 'Could not resolve host',
            'dns_transient' => 'Could not resolve host: temporary failure in name resolution',
            'unroutable' => 'Failed to connect: network is unreachable',
            'no_route' => 'Failed to connect: no route to host',
            'refused' => 'Failed to connect: connection refused',
            'timeout' => 'Connection timed out after 10000 ms',
            'validation' => 'URL host is not allowed',
            default => null,
        };
    }

    private static function pick(string $key, string $salt, int $mod): int
    {
        return (int) (hexdec(substr(hash('sha256', $salt . '|' . $key), 0, 7)) % max(1, $mod));
    }

    /** The host a stored node key names: a generated host's name, or a leaked host as the key spells it. */
    public function hostOf(string $key): string
    {
        if (preg_match('/\Ag(\d{1,5})\z/', $key, $m) === 1) {
            return $this->net->generated()->name((int) $m[1]) ?? $this->net->generated()->ip((int) $m[1]);
        }
        $colon = strpos($key, ':');

        return $colon === false ? $key : substr($key, $colon + 1);
    }

    /** The service word a node is named after. */
    public static function stem(NetNode $node): string
    {
        $first = explode('.', $node->host)[0];
        $stem = (string) preg_replace('/-[0-9a-z]{6}\z/', '', $first);
        $stem = (string) preg_replace('/[^a-z]/', '', strtolower($stem));

        return $stem !== '' ? substr($stem, 0, 16) : 'service';
    }

    /** @return list<string> "host:port" neighbours a node's listing names */
    public function neighbours(NetNode $node): array
    {
        $n = 6 + self::pick($node->key, 'n', 7);
        $leaked = $this->net->providers()->sample($node->key, 1 + self::pick($node->key, 'share', 3));
        $out = [...$leaked, ...$this->net->generated()->sample($node->key, $n - count($leaked))];

        return array_values(array_unique(array_slice($out, 0, $n)));
    }

    private static function version(string $key): string
    {
        return (1 + self::pick($key, 'major', 4)) . '.' . self::pick($key, 'minor', 30) . '.' . self::pick($key, 'patch', 12);
    }

    /**
     * The answer for an outcome that reached something. $verdict is the credential verdict for the
     * gateways; $requestId is the request id a gateway that returns one puts in its answer.
     */
    public function reply(Resolution $r, string $method, PathClass $pc, ?string $verdict = null, string $requestId = ''): ?Reply
    {
        return match ($r->outcome) {
            'open' => $r->node === null ? null : $this->node($r->node, $r->port, $method, $pc, $verdict, $requestId),
            'loopback' => $this->loopback($r->port, $method, $pc),
            'metadata' => self::metadata($method, $pc),
            'proxy_denied' => Reply::http(403, 'text/plain', self::PROXY_DENIED . "\n"),
            default => null,
        };
    }

    private function banner(string $key): Reply
    {
        return Reply::failure('banner', 'Received HTTP/0.9 when not allowed', self::BANNERS[self::pick($key, 'banner', count(self::BANNERS))] . "\r\n");
    }

    public function node(NetNode $node, int $port, string $method, PathClass $pc, ?string $verdict, string $requestId): Reply
    {
        if ($port === 22) {
            return $this->banner($node->key);
        }
        $m = $method === 'HEAD' ? 'GET' : $method;
        $stem = self::stem($node);

        return match ($node->kind) {
            'sts' => CredentialEndpoints::stsReply($verdict ?? 'missing', $requestId),
            'payments' => CredentialEndpoints::paymentsReply($verdict ?? 'missing'),
            'db' => Reply::failure('conn_reset', 'Recv failure: connection reset by peer'),
            'cache' => Reply::failure('empty', 'Empty reply from server'),
            'ssh' => $this->banner($node->key),
            'admin_ui' => $this->adminUi($stem, $m, $pc),
            'metrics' => $this->metrics($node, $stem, $m, $pc),
            'registry' => $this->registry($node, $stem, $m, $pc),
            default => $this->httpApi($node, $stem, $m, $pc),
        };
    }

    private static function json(int $status, array $data): Reply
    {
        return Reply::http($status, 'application/json', (string) json_encode($data, JSON_UNESCAPED_SLASHES) . "\n");
    }

    private function httpApi(NetNode $node, string $stem, string $m, PathClass $pc): Reply
    {
        if ($pc === PathClass::Health && ($m === 'GET' || $m === 'POST')) {
            return self::json(200, ['status' => 'ok', 'checks' => ['database' => 'ok', 'cache' => 'ok', 'queue' => self::pick($node->key, 'q', 4) === 0 ? 'degraded' : 'ok']]);
        }
        if ($m === 'PUT' || $m === 'DELETE' || $m === 'PATCH') {
            return self::json(405, ['error' => 'method not allowed']);
        }
        if ($m === 'POST') {
            return $pc === PathClass::Api ? self::json(400, ['error' => 'invalid request body']) : self::json(405, ['error' => 'method not allowed']);
        }
        if ($pc === PathClass::Health) {
            return self::json(200, ['status' => 'ok', 'checks' => ['database' => 'ok', 'cache' => 'ok', 'queue' => self::pick($node->key, 'q', 4) === 0 ? 'degraded' : 'ok']]);
        }
        if ($pc === PathClass::Root || $pc === PathClass::Api) {
            $deps = $this->neighbours($node);
            if ($this->net->credPointers()) {
                $deps = [...$deps, ...$this->net->credentials()->pointers()];
            }

            return self::json(200, ['service' => $stem, 'version' => self::version($node->key), 'status' => 'ok', 'dependencies' => $deps]);
        }

        return self::json(404, ['error' => 'not found']);
    }

    private function adminUi(string $stem, string $m, PathClass $pc): Reply
    {
        if ($m === 'POST') {
            return Reply::http(403, 'text/html', "<html><head><title>Forbidden</title></head><body><h1>Forbidden</h1><p>Missing session token.</p></body></html>\n");
        }
        if ($m !== 'GET') {
            return Reply::http(405, 'text/html', "<html><head><title>Method Not Allowed</title></head><body><h1>Method Not Allowed</h1></body></html>\n");
        }
        if ($pc !== PathClass::Root && $pc !== PathClass::Admin) {
            return Reply::http(404, 'text/html', "<html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>\n");
        }
        $title = ucfirst($stem) . ' console';

        return Reply::http(200, 'text/html', "<!doctype html>\n<html><head><title>Sign in · {$title}</title></head>\n<body><main>\n"
            . '<h1>' . htmlspecialchars($this->company, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . " {$title}</h1>\n"
            . "<form method=\"post\" action=\"/session\">\n<label>Username <input name=\"username\" autocomplete=\"username\"></label>\n"
            . "<label>Password <input type=\"password\" name=\"password\"></label>\n<button type=\"submit\">Sign in</button>\n</form>\n"
            . "<p>Internal use only. Sign-ins are recorded.</p>\n</main></body></html>\n");
    }

    private function metrics(NetNode $node, string $stem, string $m, PathClass $pc): Reply
    {
        if ($m !== 'GET') {
            return Reply::http(405, 'text/plain', "method not allowed\n");
        }
        if ($pc !== PathClass::Metrics && $pc !== PathClass::Root) {
            return Reply::http(404, 'text/plain', "not found\n");
        }
        $out = "# HELP {$stem}_requests_total Requests served, by upstream.\n# TYPE {$stem}_requests_total counter\n";
        $up = "# HELP {$stem}_upstream_up Whether an upstream answered its last probe.\n# TYPE {$stem}_upstream_up gauge\n";
        foreach ($this->neighbours($node) as $i => $hp) {
            $out .= "{$stem}_requests_total{upstream=\"{$hp}\"} " . (1000 + self::pick($node->key . $i, 'req', 90000)) . "\n";
            $up .= "{$stem}_upstream_up{upstream=\"{$hp}\"} " . (self::pick($node->key . $i, 'up', 9) === 0 ? 0 : 1) . "\n";
        }

        return Reply::http(200, 'text/plain; version=0.0.4', $out . $up);
    }

    private function registry(NetNode $node, string $stem, string $m, PathClass $pc): Reply
    {
        if ($m !== 'GET') {
            return self::json(405, ['error' => 'method not allowed']);
        }
        if ($pc === PathClass::Api) {
            return self::json(401, ['error' => 'authentication required']);
        }
        if ($pc !== PathClass::Root) {
            return self::json(404, ['error' => 'not found']);
        }

        return self::json(200, ['registry' => $stem, 'version' => self::version($node->key), 'mirrors' => $this->neighbours($node)]);
    }

    /** The fetch worker's own loopback: a fixed per-deploy port map. */
    public function loopback(int $port, string $method, PathClass $pc): ?Reply
    {
        return match ($port) {
            22 => $this->banner('loopback'),
            6379 => Reply::failure('empty', 'Empty reply from server'),
            8080 => $method === 'GET' || $method === 'HEAD'
                ? Reply::http(200, 'text/html', "<!doctype html>\n<html><head><title>Sign in · Delivery worker</title></head>\n<body><main><h1>Delivery worker</h1>\n"
                    . "<form method=\"post\" action=\"/login\"><label>Operator <input name=\"operator\"></label>\n"
                    . "<label>Password <input type=\"password\" name=\"password\"></label><button type=\"submit\">Sign in</button></form>\n</main></body></html>\n")
                : Reply::http(403, 'text/html', "<html><body><h1>Forbidden</h1></body></html>\n"),
            9090 => $method === 'GET' || $method === 'HEAD'
                ? Reply::http(200, 'text/plain; version=0.0.4', "# HELP delivery_worker_queue_depth Deliveries waiting, by queue.\n# TYPE delivery_worker_queue_depth gauge\n"
                    . "delivery_worker_queue_depth{queue=\"hooks\"} 3\ndelivery_worker_queue_depth{queue=\"imports\"} 1\ndelivery_worker_queue_depth{queue=\"exports\"} 0\n"
                    . "# HELP delivery_worker_attempts_total Delivery attempts, by result.\n# TYPE delivery_worker_attempts_total counter\n"
                    . "delivery_worker_attempts_total{result=\"delivered\"} 48213\ndelivery_worker_attempts_total{result=\"failed\"} 1907\n")
                : Reply::http(405, 'text/plain', "method not allowed\n"),
            default => null,
        };
    }

    /**
     * Instance metadata with session tokens required: every read is 401, a token request without its
     * TTL header is 400, and any other PUT is 403. No primitive here sends a custom header, so no token
     * is ever issued.
     */
    public static function metadata(string $method, PathClass $pc): Reply
    {
        if ($method === 'PUT') {
            return Reply::http($pc === PathClass::Token ? 400 : 403, 'text/plain', '');
        }

        return Reply::http(401, 'text/plain', '');
    }
}
