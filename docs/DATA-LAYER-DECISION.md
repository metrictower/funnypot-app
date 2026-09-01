# FunnyPot Data-Layer Decision

Status: decision memo. Answers APP-REDESIGN.md section 4 (data layer) and the
storage half of section 5 (blocklist cache). Grounded in the current code
(`demo/lib/store.php`, `demo/lib/geo.php`, `demo/index.php`, `demo/listen.php`,
`demo/fpm-pool.conf`) and one measured fact: a full real-nuclei scan logged
~1000 hits at ~29 requests/sec with 0 timeouts, through today's double-write
path (JSON-lines file with LOCK_EX, then a SQLite mirror insert).

Decision up front: **SQLite-canonical, one file per concern, no second
service.** Runner-up: Postgres-for-all. Full reasoning below.

---

## 1. "SQLite is the budget/demo DB" - where that is true and where it is a myth

The suspicion deserves a straight answer, because it drives the whole choice.

### The concurrency model, stated correctly

SQLite in WAL mode is **many concurrent readers plus one writer at a time**.
Readers never block the writer and the writer never blocks readers. Writes
serialize on a per-database-file lock; each single-row insert holds that lock
for tens of microseconds. With `busy_timeout` set (the code already sets
3000ms), a writer that finds the lock held **queues and retries** instead of
erroring. With `synchronous=NORMAL` in WAL (also already set), a commit is an
append to the WAL file with no fsync; fsync happens at checkpoint. The old
"SQLite is one reader OR one writer" claim describes rollback-journal mode from
years ago and is false for this configuration.

What that buys in practice: on ordinary SSD hardware, cross-process single-row
commits sustain on the order of **2,000 to 20,000 per second** (lock handoff
dominated, not I/O dominated). Take the conservative end, 2,000/sec, as the
planning number.

### Where "budget DB" is TRUE

- Many writers holding **long** write transactions. The lock is per-file, so a
  bulk 30-second import transaction blocks every other writer to that file for
  30 seconds. (This matters below; it is the one real trap in this app.)
- More than one **host** needing the same database. SQLite is a file on a local
  filesystem; there is no network protocol, and WAL does not work over NFS.
- HA / hot standby / failover.
- Rich types and server-side features: native `inet`/`cidr`, GiST indexes,
  stored procedures, a scheduler (`pg_cron`), roles.
- Sustained heavy analytics concurrent with heavy writes on the same file,
  because a long-running read transaction pins the WAL and delays checkpoints,
  growing the WAL file.

### Where it is a MYTH

- "It cannot take concurrent write load." This app's writers are 16 php-fpm
  workers plus 18 single-process listeners, roughly 34 connections, each doing
  sub-millisecond single-row inserts. That is the textbook WAL-friendly shape.
  The measured 29 req/sec burst used about **1.5% of the conservative
  throughput budget**, and it did so while ALSO paying for a second serialized
  write (the JSON file append under LOCK_EX, which is itself a cross-process
  serialization point). Dropping the file to optional-export makes the SQLite
  path the only write, i.e. faster than what was measured.
- "Serious deployments need a server DB." Serious means: survives bursts, has
  a backup story, has retention, queries fast. All four are available in
  SQLite at this scale, and one of them (a hard on-disk size cap) is actually
  **easier** in SQLite than in Postgres (section 3).

Verdict: for a single-box appliance with this write shape, "SQLite is the demo
DB" is a myth. It becomes true the day there is a second box or a central
aggregation store.

---

## 2. Real load profile of one internet-facing honeypot IP

### Steady background noise

A single exposed IPv4 gets unsolicited probes within minutes of coming up.
For a quiet IP the commonly observed volume is hundreds to a few thousand
connection attempts per day; once Shodan/Censys index a host with 18 open,
banner-answering ports, expect it to climb to tens of thousands of events per
day. Call it **1,000 to 90,000 logged events/day, i.e. 0.01 to 1 write/sec
average**. Rounded: background noise is less than one write per second
essentially always.

### Bursts

- Measured: a full nuclei run at **~29 req/sec**, ~1000 hits, 0 timeouts.
- Worst realistic case: a dirbusting tool (ffuf/feroxbuster) at high
  concurrency. The ceiling is set by the honeypot itself, not the attacker:
  16 fpm workers at 5-20ms per request caps HTTP at roughly **800-3,000
  req/sec theoretical, a few hundred in practice** once the deliberate latency
  jitter (default 40ms) is on. The TCP listeners add connect/command events at
  most in the tens per second (credential stuffing on SSH/telnet).
- So the worst-case aggregate write burst is on the order of **a few hundred
  writes/sec for minutes**, against a conservative SQLite budget of ~2,000/sec.

### When would SQLite actually be stressed

Two conditions, and only these:

1. Sustained aggregate writes in the **thousands per second**, which this box
   cannot generate because fpm and the listeners throttle first.
2. A **long write transaction on the hits file** during a burst (for example a
   bulk blocklist refresh in the same database), which would queue ingest
   writes past the 3s busy_timeout and drop inserts. This is a design mistake,
   not a capacity limit, and the design below removes it structurally.

Plain conclusion: this workload does not stress SQLite. It idles it.

---

## 3. Options A / B / C against the requirements

The store must serve: burst ingest from ~34 processes; dashboard aggregates
(top talkers, templates, hourly histogram, geo map, click-to-filter); IP
blocklist membership including CIDR; GeoIP range lookups; retention by
max-days AND max-GB; a known_attacker flag.

### A. SQLite-only (WAL, tuned)

- **Load headroom:** ~2,000/sec conservative vs a few hundred worst case.
  10x headroom minimum. PASS.
- **Services:** zero beyond the existing processes. Best possible score on
  Bob's minimize-services goal.
- **Backup:** it is a file. `VACUUM INTO 'snapshot.db'` gives a consistent
  online snapshot; add Litestream (one ~10MB static binary the entrypoint can
  supervise) for continuous streaming replication to S3 with point-in-time
  restore. That backup story beats a nightly pg_dump.
- **RAM:** a few MB of page cache per connection. Effectively free.
- **Dashboard aggregates:** the current widget queries are full-table GROUP
  BYs (including a `json_each` join) run every 3 seconds per open dashboard.
  That is the ONE thing that degrades in any engine as the table grows. Two
  cheap fixes, both engine-independent: retention caps the raw table (30 days
  at heavy noise is ~1-3M rows, where these scans are still sub-second), and a
  small hourly rollup table plus maintained counters makes the widget tick
  O(1) regardless of history. Do the rollup; it is a day of work.
  > **Built — FP-0243a.** The rollup shipped, at a finer (per-minute) grain so
  > events-over-time is meaningful, folded up to hour + day for history. A
  > background worker (`demo/rollup.php`, on a ~15s entrypoint timer) reads new
  > `hits` since a watermark and UPSERTs a `rollup` table in `hits.db`
  > (`Storage\AnalyticsStore`); the analytics reads (`breakdown`/`series`) are
  > O(buckets), flat in event volume. Ingest (`append()`) is untouched — the
  > worker, not the hot path, pays for analytics.
- **CIDR blocklist:** SQLite has no `inet` type. Store ranges as integer
  `(lo, hi)` pairs with an index, exactly the trick `geo.php` already uses in
  production in this repo. Exact-IP sources are a PK lookup. IPv6 needs the
  two-64-bit-halves (or 16-byte blob) encoding, which is mild but honest
  extra code. Per-hit membership check is one indexed lookup, microseconds.
- **Geo ranges:** already SQLite, already working.
- **Retention:** max-days is `DELETE WHERE ts < cutoff`. Max-GB is
  `PRAGMA page_count * page_size`, delete oldest in chunks, and
  `auto_vacuum=INCREMENTAL` to hand pages back. A hard disk cap is a native
  strength: the whole database is one file you can measure and shrink.
- **The one real trap:** the per-file write lock. A bulk blocklist refresh
  (85 sources, potentially a million rows) must NEVER run inside the hits
  database file. Rule: **one SQLite file per concern** - `hits.db`,
  `intel.db`, `geo.db` (geo is already separate). Then a 30-second intel
  refresh transaction contends with nothing; ingest never waits on it. The
  app already runs this multi-file pattern today; keep it deliberate.

### B. SQLite + Redis

Redis would provide O(1) SISMEMBER blocklist membership and an ingest buffer.
Judge each: the SQLite indexed lookup is already microseconds per hit at
honeypot rates, so SISMEMBER buys nothing measurable; the ingest buffer solves
a write-pressure problem section 2 shows does not exist. Costs: one more
always-on service to run, monitor, and restart; ~60-100MB RAM for
million-member sets; a new silent failure mode (Redis down means blocklist
flagging quietly stops, or worse, buffered hits are lost). This is the
iCabbiTools design ported at 1000x the scale it is needed here. It is cargo
cult for this box. REJECT for the default build. (The `HitStore`-style
interface can still allow a Redis cache backend later; do not ship it.)

### C. Postgres-for-all (LOGGED hits + UNLOGGED cache tables + pg_cron)

Honest credit first: this is a coherent, well-known pattern, and it is the
RIGHT answer for a different version of this project. Native `inet`/`cidr`
with GiST kills the lo/hi encoding (including IPv6) outright; UNLOGGED tables
are a genuinely good Redis substitute; MVCC means truly concurrent writers;
one engine holds everything.

Against this box's requirements:

- **Load headroom:** enormous, and entirely unused. Postgres's concurrency
  advantage (many simultaneous writers) addresses a bottleneck this workload
  never reaches.
- **Services:** one more always-on server process, ~100-300MB practical RAM
  baseline, connection management for ~34 clients (or add pgbouncer, which is
  service number two), plus the `pg_cron` extension to install and configure.
  Directly against the minimize-services goal.
- **Backup:** needs a real pipeline (pg_dump cron or wal-g/pgBackRest). All
  fine, all more moving parts than copying or streaming a file.
- **Retention max-GB:** genuinely WORSE than SQLite. DELETE does not shrink a
  Postgres table; reclaiming disk needs VACUUM FULL (exclusive lock) or
  pg_repack (another extension). A hard "never exceed N GB on this appliance
  disk" is awkward to guarantee. For an unattended internet-facing box, that
  is not a small point.
- **Ops burden:** a superuser-owned network service running next to software
  whose entire purpose is to attract attackers. Local-socket-only mitigates
  it, but the surface and the patch cadence are real.

REJECT for the single-box appliance. ADOPT the moment there is a fleet
(section 5's flip condition), and the `HitStore` interface from APP-REDESIGN
section 4 is exactly the seam that makes that adoption cheap.

---

## 4. Alternatives considered freely

- **DuckDB:** columnar, superb at analytics, but single-writer with no
  cross-process WAL story like SQLite's. 34 writer processes is the one shape
  it is wrong for. Would win only as a read-only sidecar querying exported
  history. No.
- **ClickHouse:** the right engine at billions of rows and a fleet of sensors
  streaming into one place. On one box it is a memory-hungry service replacing
  a file. Wins only at central-aggregation scale, and even then Postgres gets
  there first. No.
- **rqlite:** SQLite behind Raft, for multi-node HA. Adds a network service to
  get availability this appliance does not need. No.
- **Litestream:** not a database, but the missing piece that makes option A
  "serious": continuous WAL streaming to S3, point-in-time restore, one static
  binary, near-zero RAM. ADOPT as the optional backup story for A.
- **Valkey/KeyDB:** same analysis as Redis (option B). No.
- **Embedded/managed Postgres:** managed moves the data off-box (latency on
  every write, a network dependency in the ingest path of a honeypot); an
  embedded pg is still pg ops in a trenchcoat. No.

---

## 5. Ranked recommendation

### 1st choice: A-plus - SQLite canonical, one file per concern, Litestream optional

Concretely:

1. Make SQLite **canonical** (APP-REDESIGN section 4 Option 1); the JSON-lines
   log becomes an optional export. This removes the LOCK_EX file append from
   the hot path, so the new write path is strictly cheaper than the one that
   already survived the measured scan with zero timeouts.
2. Three database files behind the `HitStore`/intel interfaces: `hits.db`
   (WAL, synchronous=NORMAL, busy_timeout, auto_vacuum=INCREMENTAL),
   `intel.db` (blocklist lo/hi ranges + exact IPs + AbuseIPDB TTL rows;
   bulk refreshes transact here and contend with nothing), `geo.db`
   (unchanged). Per-file write locks make cross-concern contention
   structurally impossible.
   > **Extended — FP-0242a.** A fourth per-concern file, `config.sqlite`,
   > holds the runtime config store (operator overrides + audit + a
   > monotonic generation counter). It reuses the same `Storage\Sqlite::open`
   > pragmas, and its write shape is the polar opposite of a stress case:
   > a handful of tiny single-row upserts, only when an operator edits a
   > knob. Reads are served from an APCu snapshot (php-fpm) / a per-process
   > memo (listeners), invalidated across processes by a `config.gen`
   > sentinel file, so the hot path pays at most one small `SELECT` on a
   > generation change and nothing between changes. Keeping it in its own
   > file (not `hits.db`) preserves the one-file-per-concern rule.
3. An hourly rollup table plus maintained counters so the 3-second dashboard
   tick stops doing full-table GROUP BYs. This is the only real scaling work,
   and it would be needed under Postgres too.
4. `known_attacker` computed at write time via one indexed intel lookup.
5. Retention: days prune plus the page_count*page_size GB cap, on the cron the
   entrypoint already installs for blocklist refresh.
6. Optional `FUNNYPOT_BACKUP_*`: Litestream sidecar for operators who want
   continuous offsite backup; `VACUUM INTO` for everyone else.

Why it wins: it matches the measured load with 10x headroom, it is the only
option with **zero** additional services, its backup and disk-cap stories are
the best of the three, and every requirement on the list (aggregates, CIDR,
geo, retention, flag) has a proven in-repo or standard-SQLite answer.

### Runner-up: C - Postgres-for-all

The correct architecture for the fleet version of funnypot, and the UNLOGGED
cache pattern legitimately replaces Redis. Its concrete failure mode on
today's box: you pay a permanent tax (an always-on server, 100-300MB RAM,
connection management, a backup pipeline, an awkward disk-size cap, a bigger
attack surface on a machine built to be attacked) to buy write concurrency
the workload never uses. That is capacity insurance priced at more than the
asset.

### Loser worth naming: B - SQLite + Redis

Its failure mode: a second service whose only jobs (O(1) membership, ingest
buffering) duplicate things SQLite already does fast enough by two orders of
magnitude, while adding a silent degradation path when Redis is down and RAM
pressure on a small box.

### The single fact that would flip the recommendation

**A plan to run more than one honeypot node reporting into one store.** The
moment a second box (or a central dashboard over several sensors) is real,
SQLite's file-on-one-host model is disqualified, and the answer flips to
option C, Postgres-for-all, with the UNLOGGED-cache pattern instead of Redis.
Nothing else plausibly flips it: box RAM only strengthens SQLite (it is the
smallest), and even a 10x traffic misestimate stays inside its budget.
