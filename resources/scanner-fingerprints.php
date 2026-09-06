<?php

declare(strict_types=1);

// Scanner-attribution fingerprint pack: the fixed canary tokens, signature paths/headers and
// self-declared User-Agents that specific scanners EMIT, mapped to a closed-vocabulary tool name.
// Consumed by src/App/ThreatIntel/ScannerAttributor.php to name the tool behind an HTTP probe for the
// dashboard's existing `tool` column — advisory only. Same posture as app-fingerprint-denylist.php:
// hand-curated, append-only, opcache-friendly literal, no compile step.
//
// This is INPUT-MATCHING data, never served. The needles legitimately carry scanner vocabulary
// (that is the whole point) and are safe precisely because they are only ever compared against inbound
// request bytes and never rendered into a response. Deliberately NOT under resources/compiled/ so the
// fingerprint-safety gates (which scan served artifacts) never treat these needles as leaked output.
// The `tool` labels ARE emitted (to the log/dashboard), so they stay short lowercase tool names and
// are gate-checked against the app denylist by tests/App/FingerprintSafetyTest.php.
//
// Row schema (validated on load by ScannerAttributor::validatePack):
//   surface   'ua' | 'path' | 'params' | 'target' | 'header'
//               - params: ONE decoded query+body surface, so an injected token attributes from GET or
//                 POST alike (never pinned to a named field or one method).
//               - target: ONE decoded path+query surface, for a token a tool injects into the request
//                 target via CRLF (NOT a real inbound header — PHP would never surface it as one).
//               - path:   the decoded request path only.
//               - ua:     the User-Agent value.
//               - header: a genuine inbound request header (needle '' means presence alone attributes).
//   needle    literal substring, matched case-insensitively (stripos). Mutually exclusive with matcher.
//   matcher   structured bounded matcher; the only kind is 'fence_pair' (tplmap's numeric SSTI fences).
//   header    the header name (surface 'header' only).
//   tool      CLOSED-VOCABULARY label written to the `tool` column — never attacker bytes.
//   confidence 'high'  = a token/path/header a real client never emits (attribution is near-certain).
//              'medium' = a self-declared UA needle (spoofable, but standard and worth logging).
//   version   optional anchored+bounded extractor {re, group} carried on the DTO only; V1 never
//             persists it (a spoofable version string must not enter the bounded `tool` rollup dim).
//
// Most-specific first: the first row that fires wins, so high-precision canary tells outrank the
// spoofable UA needles below them.
return [
    // --- high precision: canary tokens a real client never sends (attribution is near-certain) ---

    // dalfox / ghauri / XSStrike spray a fixed sentinel into whatever parameter carries the value, so
    // they match the combined decoded query+body surface and attribute from GET or POST alike.
    ['surface' => 'params', 'needle' => 'dlfx_sentinel_q_8a3f', 'tool' => 'dalfox',   'confidence' => 'high'],
    ['surface' => 'params', 'needle' => 'r0oth3x49',            'tool' => 'ghauri',   'confidence' => 'high'],
    ['surface' => 'params', 'needle' => 'v3dm0s',               'tool' => 'xsstrike', 'confidence' => 'high'],

    // Acunetix parameter canary and katana's form-fill password — both unique enough to be near-certain.
    ['surface' => 'params', 'needle' => 'wa_test_',        'tool' => 'acunetix', 'confidence' => 'high'],
    ['surface' => 'params', 'needle' => 'katanap@assw0rd1', 'tool' => 'katana',  'confidence' => 'high'],

    // tplmap wraps its SSTI probe in two numeric fences: {{<10 digits>}}payload{{<10 digits>}}. Matched
    // by a linear, fixed-slice, bounded-gap scan (never an arbitrary-gap regex) — see fence_pair below.
    ['surface' => 'params', 'matcher' => ['kind' => 'fence_pair', 'max_gap' => 256, 'max_starts' => 128],
        'tool' => 'tplmap', 'confidence' => 'high'],

    // CRLFuzz injects this token into the request target via CRLF; it is visible on the decoded
    // path/query surface, NOT as a legitimate inbound header (see the schema note on 'target' above).
    ['surface' => 'target', 'needle' => 'x-injected-header-by', 'tool' => 'crlfuzz', 'confidence' => 'high'],

    // jaeles baselines every host with this fixed probe path.
    ['surface' => 'path', 'needle' => '/hopefully404.lock', 'tool' => 'jaeles', 'confidence' => 'high'],

    // Nessus WAS allows an operator to stamp this header for upstream allowlisting; its presence alone
    // is a strong tell a normal client never carries.
    ['surface' => 'header', 'header' => 'X-Nessus-Scan', 'needle' => '', 'tool' => 'nessus', 'confidence' => 'high'],

    // --- medium: self-declared User-Agent needles (spoofable, but standard and worth logging) ---

    // sqlmap declares a parseable version; capture it on the DTO only (bounded, anchored) — never
    // persisted, never spliced into the bounded `tool` name.
    ['surface' => 'ua', 'needle' => 'sqlmap', 'tool' => 'sqlmap', 'confidence' => 'medium',
        'version' => ['re' => '~\Asqlmap/(\d{1,3}(?:\.\d{1,3}){1,3})(?:[^0-9].{0,64})?\z~D', 'group' => 1]],
    ['surface' => 'ua', 'needle' => 'nikto',       'tool' => 'nikto',       'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'nuclei',      'tool' => 'nuclei',      'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'wpscan',      'tool' => 'wpscan',      'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'feroxbuster', 'tool' => 'feroxbuster', 'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'gobuster',    'tool' => 'gobuster',    'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'dirbuster',   'tool' => 'dirbuster',   'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'commix',      'tool' => 'commix',      'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'zgrab',       'tool' => 'zgrab',       'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'arachni',     'tool' => 'arachni',     'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'masscan',     'tool' => 'masscan',     'confidence' => 'medium'],
    ['surface' => 'ua', 'needle' => 'nmap',        'tool' => 'nmap',        'confidence' => 'medium'],
];
