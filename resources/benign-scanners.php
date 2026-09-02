<?php

declare(strict_types=1);

// FP-0247 (Fix C): curated never-report allowlist of documented benign internet-measurement /
// security-research scanners. funnypot must never publicly accuse this infrastructure of attacking
// (it burns the operator's AbuseIPDB reputation and wrongly names known-good research hosts).
//
// SAFETY DIRECTION: matching an entry here can ONLY SUPPRESS a report — it can never cause one. An
// over-broad or stale entry therefore fails safe: at worst a real attacker inside a listed range is
// not reported (lost intel), never an innocent party wrongly reported. Keep this hand-curated and
// APPEND-ONLY, and cite the published source for every entry (mirrors resources/app-fingerprint-
// denylist.php conventions). Consumed by src/App/ThreatIntel/BenignScanners.php.
//
// Format: 'Org label' => ['<cidr-or-exact-ip>', ...] (IPv4 + IPv6, exact IPs allowed).

return [
    // Censys — official published scan ranges.
    // https://support.censys.io/hc/en-us/articles/360043177092 ("What are the IP addresses ... Censys scans from")
    'Censys' => [
        '162.142.125.0/24',
        '167.94.138.0/24',
        '167.94.145.0/24',
        '167.94.146.0/24',
        '167.248.133.0/24',
        '199.45.154.0/24',
        '199.45.155.0/24',
        '206.168.34.0/24',
        '2602:80d:1000:b0cc:e::/80',
        '2620:96:e000:b0cc:e::/80',
    ],

    // Shodan — no official CIDR publication; these are its long-observed census scanner ranges
    // (reverse DNS census*.shodan.io / *.shodan.io). Best-effort, append-only.
    'Shodan' => [
        '198.20.69.0/24',
        '198.20.70.0/24',
        '66.240.192.0/18',
        '71.6.128.0/17',
        '80.82.77.0/24',
    ],

    // Shadowserver Foundation — non-profit; scans hosted in Hurricane Electric ranges.
    // https://www.shadowserver.org/what-we-do/network-reporting/get-reports/ (scanning source ranges)
    'Shadowserver' => [
        '64.62.128.0/17',
        '184.105.0.0/16',
        '216.218.128.0/17',
        '74.82.47.0/24',
    ],

    // University of Michigan — academic internet-wide measurement (the origin of ZMap/Censys).
    // Scans from the 141.212.121.0/24 and 141.212.122.0/24 subnets (researchscan.eecs.umich.edu).
    'University of Michigan (research)' => [
        '141.212.121.0/24',
        '141.212.122.0/24',
    ],

    // GreyNoise — primarily a passive-sensor / RIOT lookup provider rather than a bulk scanner; it
    // publishes no fixed scanner CIDR. Left as a documented placeholder so the org is tracked here;
    // add exact IPs only when GreyNoise publishes them. (See https://docs.greynoise.io/ RIOT.)
    // 'GreyNoise' => [ ... ],
];
