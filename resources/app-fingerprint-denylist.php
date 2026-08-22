<?php

declare(strict_types=1);

// App-side mirror of funnypot-core's resources/fingerprint-denylist.php. Substrings and patterns
// that must NEVER appear in output this app generates or serves — hand-authored skins
// (src/App/Render/Skins/*, GenericSkin) and the LLM prompt exemplars (src/App/Llm/LlmPromptBuilder.php)
// alike. A hit means an upstream detection source's own vocabulary (or a retired public bait value)
// leaked into what funnypot serves back, which lets a classifier recognise the reply as canned/templated
// instead of a plausible real response — the one thing this app's deception surface exists to prevent.
//
// This copy is intentionally self-contained: funnypot-core is a `dev-main` vendor dependency here,
// not something this app's CI can assume is present/unmodified at scan time, so the canonical entries
// are mirrored in rather than required from vendor/. Keep it hand-curated and append-only, same as
// the core file. Consumed by tests/App/FingerprintSafetyTest.php.

return [
    // Literal signature substrings (case-insensitive match).
    'literals' => [
        // --- Canonical upstream-detector vocabulary, mirrored from funnypot-core's denylist ---
        'OWASP_CRS',
        'OWASP CRS',
        'ModSecurity',
        'Coraza',
        'libinjection',
        'paranoia-level',
        'inbound_anomaly_score',
        'crs-setup',
        'SecRule',

        // --- Retired public bait literals: values from an earlier iteration of this app's
        // hand-authored HTML/exemplars that leaked into a public repo/history. Once a literal has
        // been publicly visible, a classifier can match it verbatim forever after, so it stays
        // permanently denylisted even though the app no longer intentionally emits it. ---
        'tok_9f3ac21e',
        'acme portal',
        'a.reyes',
        '9f3ac2',
    ],
    // Regex signatures (given without delimiters; matched case-insensitively).
    'patterns' => [
        // A bare CRS rule id: six digits in the 9xxxxx request-rule range, not part of a longer
        // number. Serving one back would echo CRS's own rule numbering.
        // Excludes a run immediately preceded by `#` or another hex digit, so a seed-derived
        // 6-hex-digit accent color like #912345 (all-decimal hex just happens to look like a
        // rule id) isn't misread as one — a hex color is not a CRS rule id.
        '(?<![#0-9a-fA-F])9\d{5}(?![0-9a-fA-F])\b',
        // ModSecurity with an underscore/hyphen separator (mod_security, mod-security,
        // mod_security_id …); the bare `ModSecurity` literal misses these variants.
        'mod[_-]?security',
    ],
];
