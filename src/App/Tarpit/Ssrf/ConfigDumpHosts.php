<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\ConfigDump;

/**
 * The hosts /admin/export/settings.py names, so a host read there resolves on the fake network.
 *
 * The preamble's hosts match exactly: db-primary.<region>.internal:5432, app.<domain> and
 * internal.<domain>. Each section names svc-<slug>.<region4>.<domain> and
 * cache-<slug>.<region4>.internal; those match by shape and are confirmed against the key index, which
 * covers every section the configured cap can serve. A shaped name the index does not hold yet answers
 * as a transient resolver failure, never as a name that does not exist, so no later answer
 * contradicts it.
 */
final class ConfigDumpHosts implements HostDirectory
{
    public function __construct(
        private ConfigDump $dump,
        private string $domain,
        private string $region,
        private int $sections,
        private KeyIndexView $index,
    ) {
    }

    public function lookup(string $host): ?NetNode
    {
        if ($host === 'db-primary.' . $this->region . '.internal') {
            return new NetNode('cd:db', 'db', $host, [5432]);
        }
        if ($this->domain !== '' && ($host === 'app.' . $this->domain || $host === 'internal.' . $this->domain)) {
            return new NetNode('cd:' . $host, 'admin_ui', $host, [80, 443]);
        }
        $svc = $this->domain !== '' && str_ends_with($host, '.' . $this->domain)
            && preg_match('/\Asvc-[a-z0-9]{6}\.[a-z0-9]{4}\z/', substr($host, 0, -strlen($this->domain) - 1)) === 1;
        $cache = preg_match('/\Acache-[a-z0-9]{6}\.[a-z0-9]{4}\.internal\z/', $host) === 1;
        if (!$svc && !$cache) {
            return null;
        }
        if ($this->index->contains('host', $host)) {
            return $svc ? new NetNode('cd:' . $host, 'http_api', $host, [443]) : new NetNode('cd:' . $host, 'cache', $host, [6379]);
        }

        return $this->index->complete() ? null : NetNode::transient($host);
    }

    public function sample(string $label, int $n): array
    {
        if ($n < 1 || $this->sections < 1) {
            return [];
        }
        $k = (int) (hexdec(substr(hash('sha256', 'cdhosts|' . $label), 0, 7)) % $this->sections);
        $f = $this->dump->sectionFacts($k);
        $out = [$f['svcHost'] . ':443', $f['cacheHost'] . ':6379', 'db-primary.' . $this->region . '.internal:5432'];

        return array_slice($out, 0, $n);
    }
}
