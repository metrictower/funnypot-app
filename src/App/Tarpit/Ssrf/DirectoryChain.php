<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/** Providers in order; the first one that knows a host answers for it. */
final class DirectoryChain implements HostDirectory
{
    /** @param list<HostDirectory> $providers */
    public function __construct(private array $providers)
    {
    }

    public function with(HostDirectory $provider): self
    {
        return new self([...$this->providers, $provider]);
    }

    public function lookup(string $host): ?NetNode
    {
        foreach ($this->providers as $p) {
            $node = $p->lookup($host);
            if ($node !== null) {
                return $node;
            }
        }

        return null;
    }

    /** One host from each provider in turn, so every provider gets a fixed share of a listing. */
    public function sample(string $label, int $n): array
    {
        $lists = [];
        foreach ($this->providers as $i => $p) {
            $lists[] = $p->sample($label . '|' . $i, $n);
        }
        $out = [];
        for ($round = 0; count($out) < $n; $round++) {
            $added = false;
            foreach ($lists as $l) {
                if (isset($l[$round]) && count($out) < $n) {
                    $out[] = $l[$round];
                    $added = true;
                }
            }
            if (!$added) {
                break;
            }
        }

        return $out;
    }
}
