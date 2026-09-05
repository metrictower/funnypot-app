# Install identity

The honeypot's persona, fake filesystem, console sessions, Docker telemetry, engagement analytics and
core render salt all hang off ONE private root of identity per install: the **install master**. This
document is the operator's reference — what exists on disk, how it is prepared, what changes on the
first deploy after this landed, and how to back up, restore and rotate it. The code lives in
`src/App/Identity/` and `src/App/Tls/`.

## What exists

| Path | Owner / mode | Contents |
|---|---|---|
| `<storage>/.funnypot/identity/` | root 0700 | the private persistent directory (`<storage>` = the data volume, `dirname(FUNNYPOT_DB)`) |
| `…/install.secret` | root 0600, link count 1 | one line: `funnypot-install-secret-v1:` + 43 unpadded base64url chars (32 CSPRNG bytes) + LF |
| `…/install.lock` | root 0600 | the creation lock |
| `…/manifest.json` | root 0600 | secret-free: schema, source class, persona source, public persona hash, one-way keyset commitment, TLS selection + fingerprint, warning codes |
| `…/tls/{cert,key}.pem`, `provenance.json` | root 0600 | the **generated** decoy pair + its sidecar (hostname, SAN, fingerprint, time — never the key) |
| `/run/funnypot/identity-private/{shell,sip,redis,post-exploit-state}.json` | root 0700 / 0600 | root-only listener bundles |
| `/run/funnypot/identity-http/http.json` | root:www-data 0750 / 0640 | the web tier's bundle |
| `/run/funnypot/tls/{cert,key}.pem` | root | fixed links to the SELECTED pair (what nginx serves) |
| `/run/funnypot/nginx/admin-ssl.conf` | root 0600 | the rendered Let's Encrypt admin vhost, only when the live pair verified |

Every bundle carries a common envelope (`schema`, `bundle`, `source`, `public_persona_hash`,
`keyset_commitment`) and a typed payload holding only what that consumer needs:

| Bundle | Payload |
|---|---|
| `http` | persona material, core render salt, shell filesystem key, console session-MAC key, Docker registry-token key, engagement analytics key |
| `shell` | persona material, shell filesystem key |
| `sip` | persona material |
| `redis` | persona material, `redis-telemetry/v1` key |
| `post-exploit-state` | persona material, `post-exploit-state/v1` key (root-only source; the future state role receives a projected view, the sample role and every web/protocol process never see it) |

Private keys are HKDF-SHA256 outputs of the master (salt `funnypot/install-identity/v1`, one versioned
info string per domain, 32 bytes each). The API is closed: named methods only, no `derive($label)`.
The keyset commitment is `sha256` over the private `runtime-keyset-proof/v1` output, so a changed
master is detected even when a persona override keeps the visible identity constant.

## Preparation order

`php /app/bin/funnypot identity:prepare` (root, no options — the master is never accepted on argv):

1. resolve the master: `FUNNYPOT_INSTALL_SECRET_FILE` (root-owned 0600/0400, canonical path, no
   symlinks) > `FUNNYPOT_INSTALL_SECRET` (canonical line) > the persisted file > **one** CSPRNG
   creation (O_EXCL 0600 temp → write → flush → fsync → `link()` publication → dir fsync → temp unlink
   → dir fsync → read-back; 32 concurrent preparers converge on one value);
2. derive the keyset; resolve the visible persona (`FUNNYPOT_PERSONA_SEED` > legacy
   `FUNNYPOT_PERSONA_SECRET` > install-derived `fpi1_…`); verify the reserved OS principals;
3. select + verify TLS (below);
4. publish the manifest, then the runtime bundles and TLS links, atomically;
5. root-read every bundle back and compare its envelope with the manifest.

The entrypoint runs it **first**, un-guarded by `|| true`, then removes `FUNNYPOT_INSTALL_SECRET_FILE`,
`FUNNYPOT_INSTALL_SECRET`, `FUNNYPOT_PERSONA_SEED`, `FUNNYPOT_PERSONA_SECRET`, `FUNNYPOT_TLS_CERT_FILE`,
`FUNNYPOT_TLS_KEY_FILE` and `FUNNYPOT_FS_SECRET` from the environment before php-fpm, listeners or
workers start. `scripts/deploy.sh` runs the same command in the built image against the real data
volume with `--network none` and no published port BEFORE the public container is replaced; compose
has an equivalent `funnypot-prepare` one-shot the public service depends on. A failure anywhere leaves
no socket bound and no fallback identity — the web tier serves its plain 404 and logs only a code.

`php /app/bin/funnypot identity:status` prints readiness, schema, source class, persona source, the
public identity hash, TLS selection/fingerprint and warning codes. It never prints the commitment, an
override value, a key or a path. There is no UI/API to reveal, download, edit or rotate the master.

## Persona: what changes on the first deploy

Before this, an install with no persona variable used the fleet literal `funnypot`, and the fake
filesystem was keyed on `storage/fs_secret`. Now:

- **explicitly seeded installs** (`FUNNYPOT_PERSONA_SEED`/`_SECRET` set) keep their visible persona —
  the override is used verbatim — and gain private, separated security keys;
- **unconfigured installs** reroll their visible persona ONCE (company, domain, PHP version, banners),
  then stay stable for the life of the master;
- the fake filesystem rerolls ONCE (its key is now `shell-filesystem/v1`); the legacy `fs_secret` file
  is neither imported nor deleted, just ignored (`legacy-fs-secret-file-ignored` warning);
- a currently engaged attacker will see the discontinuity. Plan the first deploy accordingly.

Weak overrides — after trim/lowercase shorter than 16 characters, or exactly `funnypot`, `changeme`,
`change-me`, `default`, `test`, `example` — are accepted (they are cosmetic) but reported as
`persona-override-weak`.

## TLS

Selection precedence, fixed and verified on every boot:

1. `FUNNYPOT_TLS_CERT_FILE` + `FUNNYPOT_TLS_KEY_FILE` (both or neither; canonical paths);
2. a complete legacy `/etc/nginx/funnypot.crt` + `.key` pair;
3. the provenance-marked generated pair under the private identity directory.

Operator/legacy pairs are served byte-identical — never copied, marked, overwritten or regenerated —
and once selected they must keep being the selected pair: a missing half, a mismatched key, or a
changed fingerprint fails before nginx starts (`tls-selection-changed`). The generated pair's subject
CN and DNS SAN come from `FUNNYPOT_CN`, else the persona hostname, plus `FUNNYPOT_PUBLIC_DNS`; the
key is fresh random asymmetric material (never KDF output). Deleting a marked generated pair
regenerates it with the same subject/SAN and a new key/fingerprint; an unmarked file in that slot is
refused (`tls-generated-unmarked`). The Let's Encrypt admin pair (`FUNNYPOT_LE_DOMAIN`) is the only
symlink-following exception: the live `fullchain.pem`/`privkey.pem` must point at
`../../archive/<same domain>/<name><same revision>.pem` and nothing else. Every hostname
(`FUNNYPOT_CN`, `FUNNYPOT_PUBLIC_DNS`, `FUNNYPOT_LE_DOMAIN`) must match the lowercase DNS grammar in
`src/App/Tls/DnsName.php`; `scripts/deploy.sh` and `scripts/letsencrypt.sh` apply the same grammar
(`scripts/lib/dns-name.sh`) before they build any SSH command.

## Backup, restore, rotation

- **Back up** `<storage>/.funnypot/identity/` with the data volume — it is root 0700, so host-side
  backups need `sudo`. Without it a restore produces a new identity (persona + filesystem reroll).
- **Restore** the whole directory with ownership/modes intact (`install.secret` root 0600, link count
  1; the directory 0700). A file with the wrong owner/mode, a symlink, a FIFO or a second hard link is
  refused, never repaired. The manifest and bundles are regenerated idempotently from the master.
- **Explicit source loss.** If the manifest says the install used `FUNNYPOT_INSTALL_SECRET[_FILE]` and
  the value is missing (`explicit-source-missing`) or different (`explicit-source-changed`),
  preparation fails. Restore the original value; the app never falls back to a generated identity.
  Configuring an explicit master over an install that already generated one fails too
  (`identity-source-conflict`).
- **Rotation is an explicit, offline redeploy:** stop the container, back up and remove
  `<storage>/.funnypot/identity/`, (optionally) place the new explicit master, redeploy. Everything
  keyed on the old master — persona, fake filesystem, console sessions, Docker tokens, engagement ids
  — changes. There is no online, opportunistic or admin-panel rotation.

## Failure codes

Every failure is `identity bootstrap failed: <code> (<remedy>)` with remedy ∈ `config` (an explicit
input is missing/malformed/changed), `storage` (unsafe/unwritable/corrupt persisted state), `runtime`
(a missing capability or privilege), `tls`, `accounts` (a reserved OS principal — `funnypot-state`
10005:10005, `funnypot-sample` 10006:10006 — exists with a conflicting shape). Messages never carry
secret bytes or absolute paths.
