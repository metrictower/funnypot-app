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
// the core file. Consumed by tests/App/FingerprintSafetyTest.php and tests/App/ServedSurfacesFingerprintTest.php.
//
// FP-0112: `literals`/`patterns` are the leak-IN guard (someone else's vocabulary showing up in what
// we serve). `own_vocabulary` below is the mirror-image leak-OUT guard (OUR OWN vocabulary showing up
// in what we serve) — see its own doc comment for why it is matched differently.

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

    // FP-0112: the mirror-image list. `literals`/`patterns` above guard the leak-IN direction —
    // an upstream detector's own vocabulary (OWASP_CRS, ModSecurity, …) showing up in what this app
    // serves back, which would tell a classifier its input got echoed into a canned response. This
    // section guards leak-OUT: THIS PROJECT'S own vocabulary — funnypot/honeypot/decoy/etc. — showing
    // up in a byte served to an unauthenticated client, which unmasks the box outright. That happened
    // for real: /__dl/sw.js shipped `// funnypot — endless decoy-download service worker (client-side
    // bait).` verbatim to every GET for three commits running, because nothing ever scanned for it.
    //
    // Entries here are WORD-STEM FRAGMENTS, not literal substrings — tests/App/FingerprintSafetyTest.php
    // and tests/App/ServedSurfacesFingerprintTest.php compile each one into a DELIMITER-SAFE, WHOLE-TOKEN
    // regex via `(?<![a-zA-Z0-9])` / `(?![a-zA-Z0-9])` lookaround (underscore is deliberately NOT in the
    // word-char class, so `is_decoy` / `decoy_file` / `honeypot_token` still match on the delimiter). Do
    // NOT match these as plain substrings the way `literals` above are matched — `troll` as a bare
    // substring hits every `conTROLLer` in the codebase, and `lure` hits every error-handling `failure`;
    // a gate that fires on those gets muted, and a muted gate is worse than no gate. Word-boundary
    // matching on this exact list is measured clean against `controller`/`trolley`/`failure`/`arbitrage`
    // and bites on `troll(s|ing)`/`lure(s)`/`is_decoy`/`honeypot_token`/the historical sw.js comment.
    //
    // Deliberately NOT here: bare `fp` / `fp-`. funnypot-core is still on v0.6.x here (not the v0.7.0
    // that reworks persona class naming), and it seeds real per-persona CSS class names as literal
    // `fp-xxxx` in every rendered skin (VisualPersona/PersonaIdentity's prefix). That is expected,
    // load-bearing, non-identifying output — an attacker sees a random 4-hex-char class prefix, not a
    // product name — so putting `fp` on this list would fail every skin render. `funnypot` (the whole
    // word) is what must never appear; `fp-` alone proves nothing and must stay off this list.
    //
    // Scope: served surfaces only (rendered skins, fake filesystem/host output, routers' response
    // bodies + headers, static assets, decoy archives). Explicitly NOT the LLM prompt exemplars in
    // src/App/Llm/LlmPromptBuilder.php — those are internal instructions to the local sidecar model
    // ("you are role-playing as a defensive security-research honeypot generating ENTIRELY FAKE bait
    // data") and legitimately carry this vocabulary; they are never bytes returned to a client.
    'own_vocabulary' => [
        'funnypot',
        'honeypot(?:s)?',
        'decoy(?:s)?',
        'bait',
        'lure(?:s)?',
        'tarpit(?:s)?',
        'metrictower',
        'troll(?:s|ing)?',
        'sabotage',
        'deception',
    ],
];
