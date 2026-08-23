# Admin-panel realism + fake-data catalog

Single source for the honeypot's deterministic (hash-of-seed) fake-data generators and admin-panel skins. Every value below is **resemblance-only** and **inert**: no real credentials/keys/wallets, no verbatim upstream markup, no canonical scanner-signature strings (invented rule-ids and generic messages only). All IPs are RFC1918/TEST-NET/doc ranges. Generators pick per-value via `hash(seed+slot)` → index into a vocab list, or `hash → value in [min,max]`. **Cross-panel coherence is the master invariant**: one seed → one host identity (same hostname, service tag, MACs, IPs, uptime baseline that only grows, disk-fill that only drifts up), and every panel view of that seed must agree — divergence is itself a tell.

---

## A. Coherent fake server-profile family

Seed one profile per victim. Every downstream field (CPU tile, RAM bar, load average, disk table, NIC speed, process RES sizes, GPU list) MUST be consistent with the chosen profile. Correlation rules at the end of this section are mandatory.

### A.1 Profiles

| Profile | Sockets × CPU | Cores/Threads | RAM (exact "odd" number) | Root FS | Data/array | NIC | Role vibe |
|---|---|---|---|---|---|---|---|
| **XS container** | cgroup limit 0.1–4 cores | — | 128 MiB–8 GiB | overlay | — | — | single service in a container |
| **S small-vm** | 1–2 vCPU | 1–2 | 987 MiB / 1.9 / 3.8 GiB | 19.5–39 GB | — | 1 Gbps | web/app node |
| **M medium-vm** | 4 vCPU | 4 | 7.7 / 15.6 GiB | 39–98 GB | 100–500 GB | 1 Gbps | app + small DB |
| **L large-vm** | 1× Xeon Silver 4314 | 8–16 / 16–32 | 31.3 / 62.8 GiB | 49–98 GB | 500 GB–2 TB | 10 Gbps | app/web node |
| **HUGE bare-metal (target)** | **2× Xeon Gold 6342** | **48C / 96T** | **256 GB (`263847264 kB` ≈ 251 GiB)** | 96 GB | **44 TB RAID @ 78–92% full** | 10–25 Gbps | virtualization / DB host |
| **HUGE-AMD** | 2× EPYC 7443 | 48C / 96T | 256 GB | 96 GB | 44 TB RAID | 25 Gbps | Proxmox hypervisor |
| **MONSTER** | 2× Xeon Gold 6448Y / EPYC 7763 | 64–128C / 128–256T | 512 GB–1 TB | 200 GB–1 TB | 4–48 TB | 25 Gbps | big compute |
| **MINER rig** | cheap CPU (Celeron G5905 / Pentium G6400 / Ryzen 5 5600) | 2–6 | 4–8 GiB | 120 GB SSD | — | 1 Gbps | 6–13 GPUs, see §B.6 |

### A.2 HUGE profile — canonical field set (build this first, it is the flagship)

- **CPU:** `Intel(R) Xeon(R) Gold 6342 CPU @ 2.80GHz`; `x86_64`, Little Endian, 32/64-bit; CPU(s) `96`, on-line `0-95`; Thread(s)/core `2`, Core(s)/socket `24`, Socket(s) `2`, NUMA nodes `2`; Vendor `GenuineIntel`, family `6`, model `106`, stepping `6`; MHz current jitters `800.000–3500.000` (idle `1197.443`, busy `2799.998`), max `3500.0000`, min `800.0000`, BogoMIPS `5600.00`. Caches: L1d `2.3 MiB (48)`, L1i `1.5 MiB (48)`, L2 `60 MiB (48)`, L3 `72 MiB (2)`. NUMA node0 `0-23,48-71`, node1 `24-47,72-95`. Virtualization `VT-x`. Flags: seed a subset of the long x86 flag string incl. `avx512*`, `vmx`, `aes`, `rdtscp` (AMD variant: Vendor `AuthenticAMD`, add `svm sev sev_es`, drop `avx512*`, L3 `256 MiB (8)`).
- **Memory:** MemTotal `263847264 kB`; MemFree 5–40 GiB (ex `18 GiB`); MemAvailable 120–180 GiB (ex `142 GiB`); Buffers `1.2 GiB`; Cached 60–110 GiB (ex `84 GiB`); used(top) 40–120 GiB (ex `61 GiB`); Shmem 2–8 GiB; SwapTotal `8388604 kB`, SwapFree near-full (0–512 MiB used on a healthy DB box). DIMM table: 16× `32 GB DDR4 3200 MT/s RDIMM`, locators `DIMM_A1…DIMM_H2` (or `P1-DIMMA1`), rank `2`.
- **Load & uptime:** on 96 threads — idle `0.80, 1.10, 1.35`; moderate `12.4, 10.9, 9.7`; busy `44.2, 39.1, 31.5` (keep 15-min < core count). `/proc/loadavg` procs `3/1287`. Uptime `up 143 days, 6:12` (range 20–420d). Users `1–4`.
- **Kernel/distro:** Ubuntu 22.04 (`5.15.0-113-generic`, `Ubuntu 22.04.4 LTS`) / Debian 12 (`6.1.0-21-amd64`, `bookworm`) / Rocky 9.4 (`5.14.0-427.13.1.el9_4.x86_64`, `Blue Onyx`) / Proxmox (`6.8.12-1-pve`, `pve-manager/8.2.4`, Boot Mode `EFI (Secure Boot)`).
- **Disks:** NVMe boot mirror `/dev/nvme0n1`+`/dev/nvme1n1` model `SAMSUNG MZQL21T9HCJR-00A07` → md RAID1 `/dev/md0`; SAS array 8–24× `TOSHIBA MG08ACA16TE` (16 TB) on `PERC H730P`/`MegaRAID SAS-3 3108`, RAID-6/10. `df -h`: `/boot` 1.9G 18%, `/` 96G 34%, `/var` 200G 61%, big mount `/data`|`/var/lib/vz`|`/backup` 44 TB **78–92% used** (near-full = lure). ZFS option: `rpool` 3.5T ONLINE mirror-0.
- **Network:** ifaces `eno1/eno2/enp94s0f0/bond0/vmbr0/lo`; bond `802.3ad (LACP)` 20000 Mb/s, single NIC 10000/25000 Mb/s, Full duplex, MTU 1500 (9000 storage). MAC OUIs: `3c:ec:ef` (Supermicro), `b4:96:91`/`a0:36:9f` (Intel), `e4:43:4b` (Dell). IPs `10.0.4.21/24` gw `10.0.4.1`, storage `10.10.10.x/24`, IPMI `10.0.99.x`. Counters RX `4.2 TB`/TX `9.8 TB`, errors/dropped `0`, live 1–400 Mbit/s spiking 2–6 Gbit/s.
- **Sensors:** CPU pkg `+52.0°C`/`+49.0°C` (idle 35–48, load 60–82, high 92 crit 100); per-core ±6°C; DIMM 30–55°C; Inlet 22°C / Exhaust 36°C; NVMe `+41.0°C (crit 89.8)`; fans FAN1..FAN8 idle 4800–7200 / load 9600–15000 RPM; PSU dual `1100W`/`1600W` Platinum, `PS Redundancy Full`, `310 Watts`, 220V; voltages `VCORE +0.85V`, `+12V +12.14V`, `+3.3V +3.34V`, `+5V +5.01V`, `VBAT +3.02V`.
- **DMI:** manufacturer/product from vocab (§C.1); BIOS `Dell Inc. 2.15.1 04/12/2024` UEFI Secure Boot; service tag `[A-Z0-9]{7}` (`7Q2XR4B`); machine-id 32-hex; UUID `4c4c4544-0037-…`; perf profile `virtual-host`; pending updates `47 available (12 security)` (bait).

### A.3 Mandatory correlation rules

- `load1 ≈ (cpu_busy% / 100) × cores × jitter(0.6–1.4)` — never load 40 on a 2-core box; healthy `load1 < cores`; "stressed" bait `load1 = cores × (1.2–3.0)`.
- RAM shown as the odd "minus-firmware" number (`31.3 GiB`, not `32`) — more believable.
- Disk: root 20–45% used, data/backup 75–93% (near-full = "download before it's gone").
- Full backup archive size > Σ component archives; DB rows ↔ table size via avg row-width; auto_increment next-value slightly > row count.
- Same seeded IP carries the same country/ASN in every panel; a fail2ban-banned IP also appears in auth.log failures (and optionally WAF); counts reconcile (`banned ≤ total_banned`, `blocked ≤ inspected`); timestamps monotonic within a session.
- Miner: pool-reported hashrate ≈ 97–99% of local effective; local rig UI and pool dashboard share wallet/worker/GPU list.

---

## B. Per-panel section inventories

Each family: pick one skin per seed via `hash % N` and keep chrome consistent for the whole session. Mixing skins within a persona is a tell.

### B.0 Panel-family selection weights (what scanners actually find exposed)

| Family | Skins (weight) |
|---|---|
| Server hardware | Cockpit / Proxmox / Webmin / ISPConfig |
| Hosting cPanel | cPanel 70% / Plesk 20% / DirectAdmin 10% |
| Observability | grafana 40% / prometheus 25% / netdata 15% / zabbix 12% / alertmanager 8% |
| DB admin | phpMyAdmin 70% / Adminer 20% / pgAdmin 10% |
| App admin | AdminLTE / Django / Nova / Filament / Rails Admin |
| Crypto miner | local rig UI + pool dashboard (paired) |
| Backups/files | cPanel Backup / File Manager / UpdraftPlus (top 3) + Duplicator/Duplicati/elFinder/TFM/autoindex |
| Logs/security | auth.log / fail2ban / CSF-lfd / Wazuh / WAF |

---

### B.1 Server-hardware panels (Cockpit / Proxmox / Webmin / ISPConfig)

All four surface the same `/proc`, `lscpu`, `lsblk`, `ip`, `top/ps`, lm-sensors/ipmitool facts — render one A-profile host through the chosen skin.

- **Cockpit — Overview:** Health tile (BIOS/health), Usage tile (CPU%, mem used/total), 4 sparklines (CPU/Mem/Disk-IO/Net), System-info tile (model, machine-id, asset tag, OS, kernel), Configuration tile (hostname, time, domain, perf profile, crypto policy, SSH keys). **Hardware-details** subpage: BIOS vendor/ver/date, manufacturer/product/serial, PCI device list (class/model/slot/vendor), **DIMM table** (locator/tech/size/speed/rank).
- **Proxmox — Node → Summary:** status tiles CPU%, IO-delay%, Load avg, RAM bar, HD/root bar, SWAP, CPU model line, Kernel, Boot Mode, Manager `pve-manager/8.x`, Uptime; time-series (Hour/Day/Week/Month/Year) CPU / load / memory / net.
- **Webmin — System Info / Running Processes:** load 1/5/15, running-proc count, CPU/real/virtual mem bars, disk, uptime, OS+kernel, Webmin version; **Running Processes** full `ps` table (PID, owner, %CPU, mem, command), sortable.
- **ISPConfig — Monitor → Server State:** server load, CPU info, memory, disk, services up/down, updates, mail/RAID/log states.

Field values, ranges and the process table: use A.2 wholesale. Process table (sort by CPU) seed set — PID 1 `/sbin/init`; `2891 mysql 118% 22.4% 58g /usr/sbin/mariadbd`; `4127 postgres 44.6% 23g postgres: walwriter`; `3310 root 12.3% libvirtd`; `5502 root 9.8% 16g qemu-system-x86_64 -name guest=web01`; `1180 www-data php-fpm: pool www`; `990 root nginx`; `812 redis 8.7g redis-server`; plus journald/sshd/prometheus/cron. Total procs 180–1300.

---

### B.2 Hosting control panels (cPanel / Plesk / DirectAdmin) — user-level

Seed the whole account from one primary domain (§C.2). URL surfaces: cPanel `:2083`, Plesk `:8443`, DirectAdmin `:2222`.

- **General Information (cPanel sidebar):** Current User `brightpk` (8-char trunc), Primary Domain, Shared IP (`192.185.44.128`), Home Dir `/home/<user>`, Last login IP (residential/foreign = juicy), Theme `Jupiter` / `cPanel 118.0.24` (110–124), `Apache 2.4.58`, `PHP 8.1.29` (7.4–8.3), `MariaDB 10.6.18` (10.3–10.11).
- **Statistics tiles** (`used / quota (nn.n%)` bars; push 1–3 past 80%): Disk `18.42 GB / 50 GB`; Bandwidth `212.7 GB / 1 TB`; Email `14 / 100`; MySQL DBs `9 / 50`; Subdomains `7 / ∞`; Addon `3 / 10`; FTP `5 / 20`; **Inodes `146,204 / 250,000`** (near-limit very believable); CPU `18% / 100%`; Phys Mem `412.8 MB / 1 GB`; Entry Procs `3 / 20`; I/O `1.9 MB/s / 10 MB/s`. Unlimited shows `∞`, no bar.
- **Domains table** (Domain | Doc Root | Redirects | HTTPS): mix main + addon + subdomains + parked; include juicy `staging.` (HTTPS Off) and `oldsite2019.` (forgotten).
- **Email Accounts** (Account | used/allocated | actions): 4–30 rows; include near-full `jane.doe@ 4.88 GB / 5 GB`, `admin@`, `newsletter@ 2.31 GB / ∞`.
- **MySQL Databases** (Database | Size | Users, `<cpuser>_` prefixed): include `brightpk_backup2023 1.88 GB brightpk_root` (juicy), `brightpk_wordpress 1.12 GB`, `brightpk_phpmyadmin`.
- **FTP Accounts** (login@domain | path | used/quota): include `backup@ /home/brightpk/backups 2.9 GB / 5 GB` (juicy), `client_photos@ …/gallery 3.4 GB / ∞`.
- **Cron Jobs** (min hour day month weekday | command): commands hint at secrets — `curl -s https://api…/sync?key=REDACTED`, `backup.sh --dest s3://brightpeak-backups`, `mysqldump … > …/db_weekly.sql`, `wp-cron.php`.
- **SSL/TLS Status** (Domain | Cert | Issuer | Expires | AutoSSL): mix valid + one **Expired** (`staging.` LE 2026-06-12) + one **No SSL** (`oldsite2019.`); issuers Let's Encrypt / cPanel AutoSSL / Sectigo / DigiCert / ZeroSSL; ~15% expired/expiring.
- **⭐ BACKUP section (headline lure):** Full backups `backup-8-21-2026_03-15-02_brightpk.tar.gz 4.82 GB` (month/day NOT zero-padded, time IS; weekly ~03:00; size drifts up 1–3%/wk); partials Home-Dir `.tar.gz` 1–40 GB, DB `brightpk_wordpress.sql.gz` 5 MB–2 GB, forwarders `aliases-<domain>.gz` 1–50 KB, filters `filter-<domain>.gz`. "Available for Download" grouped list, each `[Download]` → serve inert/streamed decoy, never a real archive. JetBackup/R1Soft variant: Type | Created | Size | Retention | [Download|Restore]; off-site labels `Amazon S3 (brightpeak-backups)`, `Backblaze B2`, `SFTP box-cp09.dediserv.net` (hint cloud creds).
- **Plesk deltas:** Resource-Usage cards (Web/Mail/DB/Logs split), Websites&Domains list (`/httpdocs, PHP 8.2, Disk 3.1 GB, Traffic 42 GB/mo`), DB list (Name|Type|Server|Size|Users), backups `backup_info_2508220400.xml` + `<domain>_2026-08-22_04-00.tzip`.
- **DirectAdmin deltas:** right-rail bars in MB (`Disk 18420.5 / 51200.0 MB`, `Bandwidth 212.70 / 1000.00 GB`), backups `backup-Aug-22-2026-1.tar.gz` in `/home/brightpk/backups/`.

---

### B.3 Observability (Grafana / Prometheus / Netdata / Zabbix / Alertmanager)

Seed top-level `platform`; every field inherits. Title-bar/version/favicon per §C.7.

**Grafana (flagship):**
- Chrome: left nav `Home, Dashboards, Explore, Alerting, Connections, Administration`; time-range picker (default `Last 6 hours`), refresh (default `30s`), datasource `Prometheus`/`Thanos`/`Mimir`/`Loki`.
- Dashboards list: 6–14 dashboards across folders `General/Production/Infrastructure/Kubernetes/Databases/Networking/SRE`; titles `Node Exporter Full`, `Host Overview`, `Kubernetes / Compute Resources / Cluster`, `MySQL Overview`, `NGINX Ingress Controller`, `Redis Dashboard`, `Blackbox Exporter`, `Business KPIs`.
- Stat tiles: Uptime `47 days, 18:22:41`, CPU Busy `23.4%` (green<70/amber/red>85), Sys Load 5m `1.87` (tie to cores), RAM Used `61.2%`, Root FS `78.4%` (red>90), CPU Cores from profile, Net In/Out `4.7/2.1 Mbps`, Requests/s `1.24k`, Error rate `0.37%` (red>5), p95 `184 ms`.
- Time-series panels: **USE** — CPU Usage (`system/user/iowait/softirq/steal/idle`), Memory Usage (`Used/Cached/Free/Buffers/Available/Swap`), Disk Space per mount 20–97%, Disk IOps (reads 0–1.2k/writes 0–3k), Network Traffic (bps), TCP sockets (established 40–4200, time_wait 5–18k), System Load, Context switches 2k–120k. **RED** — Request Rate 0.5–45k/s, by status (`2xx 92–99.7%, 4xx 0.2–6%, 5xx 0–3%`), Latency p50/p90/p95/p99 (8–120 / 40–800 / 90–3200 ms), heatmap buckets 5..10000 ms, Apdex 0.82–0.995. **K8s** — pods/node 8–110, container CPU 0.001–3.5 cores, mem 12 MiB–6 GiB, restarts 0–14.
- Tables: **Top Processes by CPU** (PID/User/%CPU/%MEM/Command) with juicy commands incl. a low-prob miner row `/usr/bin/xmrig --url pool.example:3333`, tunnel `ssh -R 8080:localhost:80 tunnel@10.0.0.9`, `rsync -az /data/backups/ backup@10.0.0.5:/vol/`, config-path commands `python3 /opt/etl/pipeline.py --config /etc/etl/prod.yml`. **Mounted Filesystems** (Mountpoint/Device/FS/Size/Used/Avail/Use%).
- Alert list: 4–12 rows, State (`Normal 60% / Pending 12% / Firing 20% / No Data 5% / Silenced 3%`), Severity `critical/warning/info/page`, names `HighCpuUsage, DiskSpaceLow, InstanceDown, HighRequestLatency, HTTP5xxSpike, PodCrashLoopBackOff, CertificateExpiringSoon, BackupJobFailed, ReplicationLagHigh`; summaries fill `{instance}/{value}/{mount}/{domain}`; ages `12s…2d 6h`.

**Prometheus:** `/targets` (Endpoint `http://<ip>:<port>/metrics`, State up 88%/down 12%, Labels, Last Scrape, Duration, Error). Job↔port map (§C.7). Down-row errors leak internal hosts: `dial tcp 10.4.12.55:9104: connect: connection refused`, `no route to host`, `401 Unauthorized`, `x509: certificate has expired`, `i/o timeout`. Make list 30–120 targets. `/graph` recent-query dropdown (`up`, `node_cpu_seconds_total`, `rate(...[5m])`, `histogram_quantile(0.95, ...)`); footer `1,204,883 series` (40k–6.2M). `/alerts` `/rules` (rule groups `node.rules, kubernetes-apps, prometheus, mysql.rules`; recording rules `job:node_cpu_utilization:avg1m`). `/status`+`/config`: Go `go1.22.4`, retention `30d`, flags incl. `--web.enable-admin-api` (bait), a full fake `prometheus.yml` scrape_configs + `alertmanagers: 10.x.x.x:9093`.

**Netdata:** left menu 18 sections (`System Overview, CPU, Memory, Disks, Networking Stack, Network Interfaces, Processes, Systemd Services, Applications, Containers & VMs, Docker, Databases, Web Servers, Anomaly Detection`); contexts `system.cpu/load/io/ram/net/processes`, `disk.sda`, `net.eth0`; dims with exact units (`system.cpu` % dims user/system/nice/iowait/irq/softirq/steal/guest; `system.net` kilobits/s, sent mirrored negative). Header badges: hostname, version, Live dot, `update-every 1s`, `1,842 charts` (400–4500), `12,405 metrics/s` (900–90,000). Alarms tab: `10min_cpu_usage (warning)`, `disk_space_usage (critical)`, states `CLEAR/WARNING/CRITICAL` + `for X minutes`.

**Zabbix:** nav `Monitoring, Services, Inventory, Reports, Data collection, Alerts, Administration`; dashboard widgets `Problems, Problems by severity, System information, Host availability, Top hosts, Geomap`. 6-level severity (Not classified grey → Disaster red). Problems table (Time/Severity/Recovery/Status/Host/Problem/Duration/Ack/Tags); problem names `High CPU utilization (over 90% for 5m)`, `/: Disk space is critically low (used > 90%)`, `Zabbix agent is not available (for 3m)`, `Interface eth0: Link down`, `MySQL: Service is down`. System-info widget: `Zabbix server running: Yes (localhost:10051)`, `hosts 142/6/318`, `items 18,442/210/37`, `triggers 6,204/11`, `NVPS 412.7`. Host-availability per type (`agent/SNMP/JMX/IPMI`) `138 / 4 / 6`.

**Shared fleet/label vocab:** §C.7. Timestamps: "as of" within 1–30s; alert "active since" spread 30s–6d; ISO `2026-08-23 14:07:42` or relative.

---

### B.4 DB-admin (phpMyAdmin / Adminer / pgAdmin)

Versions: phpMyAdmin `5.2.1`/`4.9.11` (older=juicier); Adminer `4.8.1`; pgAdmin `4 8.14`. Server: MySQL `8.0.36`/`5.7.44`, MariaDB `10.6.18-MariaDB`, PostgreSQL `15.7`.

- **Server-info cards:** DB card — Server `Localhost via UNIX socket`, type MySQL/MariaDB, connection `SSL is not being used` (juicy), version `8.0.36 - MySQL Community Server - GPL`, protocol `10`, User `root@localhost`/`admin@%`, charset `utf8mb4`. Web card — `Apache/2.4.52 (Ubuntu)`/`nginx/1.18.0`, client `mysqlnd 8.0.36`, PHP `8.1.2-1ubuntu2.14`.
- **Database list** (Database | Collation | Size | Tables | Rows | Data | Index | Total | Overhead): 6–18 DBs. Always include system DBs (`information_schema` ~60–80 tbl, `performance_schema` ~90–110, `mysql` ~31, `sys` ~100 views, `phpmyadmin`; PG `postgres/template0/template1`). Then loot DBs from §C.4. Aggregate ranges: small app 8–25 tbl / 5k–200k rows / 12–400 MB; medium SaaS 40–120 tbl / 500k–15M / 800 MB–12 GB; large prod 150–600 tbl / 20M–400M / 15–220 GB. Make `backup`/`old_backup`/`db_2023_backup`/`finance`/`payments_db` **large (10–80 GB)** — top hook.
- **Per-table listing** (Table | actions | Rows | Type | Collation | Size | Overhead): engines InnoDB 85% / MyISAM 10% / MEMORY/ARCHIVE/CSV; InnoDB rows are approximate — jitter ±8%. Row-count/size by role (§C.4 table): `*_meta`/`logs`/`order_items` are the biggest (tens of GB) → deepest browse rabbit-holes.
- **Structure view** (# | Name | Type | Collation | Attributes | Null | Default | Extra | Action): example `users` cols `id bigint PK ai`, `email varchar(255) UNIQUE`, `password varchar(255)` (bcrypt in browse), `api_token varchar(80) NULL`, `role enum('user','admin','superadmin')`, `is_admin tinyint(1)`, `two_factor_secret text`, `stripe_customer_id varchar(40)`, `last_login_ip varchar(45)`, timestamps. Auto_increment next-value slightly above row count.
- **Users/privileges** (User | Host | Password | Global privileges | Grant): 6–20 accounts (§C.5-db). Bait: `root@%` password Yes (remote root), `admin@%`, passwordless `test@%`, `debian-sys-maint@localhost`, `replica`/`repl`.
- **Process list** (Id | User | Host | db | Command | Time | State | Info): 4–30 rows; include live `mysqldump` row (`SELECT /*!40001 SQL_NO_CACHE */ * FROM \`order_items\``), `Binlog Dump` replica (Time 88000+), `event_scheduler` daemon. States `Sleep/Sending data/Copying to tmp table/Waiting for table metadata lock`. Kill link "works" (returns list minus row).
- **Browse view:** header `Showing rows 0 - 24 (≈ 48,213 total, Query took 0.0018 seconds)` (took 0.0004–0.42s); huge total, render only current page; pagination `> >>` for thousands of pages.
- **Fabricated cell values (inert):** bcrypt `$2y$10$`+53, legacy `*`+40hex, phpass `$P$B…`; API keys `sk_live_`+24–32, `AKIA`+16, `ghp_`+36; Stripe `cus_/ch_/pi_/sub_`+~14; cards masked `**** **** **** 4242` only (never full PAN); emails from free+corp vocab; IPs doc/RFC1918.
- **Variables/Status (~500 rows):** `max_connections 151/500/1000`, `innodb_buffer_pool_size`, `datadir /var/lib/mysql/`, `log_bin ON`, **RCE lures**: `secure_file_priv` empty + `local_infile ON` + FILE priv + `have_ssl DISABLED`. Status counters: `Uptime` 100k–30M, `Questions` 1M–8B, `Threads_connected` 2–200, `Aborted_connects` 3–9k (implies brute-force underway).
- **SQL console (interactive sink):** honor `SHOW DATABASES/TABLES`, `SELECT VERSION()/USER()`, `SELECT * FROM users LIMIT 25` (fabricated page); `INTO OUTFILE`/`LOAD_FILE()` → plausible `Query OK` or `Errcode: 13 - Permission denied` (never touch FS); real-shaped errors `#1064`, `#1146 Table doesn't exist`, `#1044 Access denied`. Reflect `information_schema` consistently (attackers cross-check counts).

---

### B.5 App-admin (AdminLTE / Django / Nova / Filament / Rails Admin)

Internal back-office of an unremarkable SaaS. Shell: product name from §C.8, user chip `AM · Aaron Mitchell · Super Admin`, sidebar `Dashboard, Users, Roles & Permissions, Teams, Billing, API Keys, Webhooks, Audit Log, Sessions, Feature Flags, Jobs & Queues, Settings, System/Health, Logs`, nav badges (unread 1–9, failed jobs 0–37), footer `v3.14.2 · build 4821`.

- **Dashboard tiles:** Total Users `48,213` (1.2k–480k), DAU 3–12% of total, MRR `$184,920` ($8k–2.4M), Open Tickets 0–340, Failed Jobs 24h 0–900, Signups Today 0–1400, Storage `4.7 TB / 8 TB`, API Calls 24h `12.4M` (40k–90M) — each with delta + sparkline.
- **Users table** (ID | Name | Email | Role | Team | Status | 2FA | Plan | Last login | Signed up | Actions): IDs seq 1–500000 or UUID; names §C.9; emails `first.last@<domain>` + juicy `admin@`/`root@`/`svc-billing@`; Status Active 85% / Invited / Suspended / Disabled; 2FA ~40% Disabled (bait); Plan Free..Enterprise; Last login relative+absolute incl. `Never`. Controls: search, per-page, sort, bulk-select, **Export CSV**, **Impersonate** (strong bait), Reset password, Delete. Detail view: deep sub-tables (activity, sessions, API keys owned, billing, danger-zone).
- **Roles & Permissions:** roles table (Role|Description|Users|Perms|Type|Updated) `Super Admin (2, 148 perms)`…`Read-only (210)`; permission matrix abilities `viewAny/view/create/update/delete/export/impersonate` × resources `User/Role/Team/Invoice/ApiKey/Webhook/FeatureFlag/AuditLog`; slugs `user.viewAny` (generic CRUD, never real signature strings); guard `web/api/sanctum`.
- **Teams/Orgs:** ID|Org|Slug|Owner|Members|Plan|Seats|MRR|Created|Status; org names `Globex, Initech, Umbrella Labs, Hooli, Vandelay Industries`; members 1–4200, seats `47/50`, MRR $0–92k.
- **Billing:** Subscriptions (status `active/trialing/past_due/canceled/unpaid`, amount $9–4999, `Visa •••• 4242` fake); Invoices `INV-2026-004821` (status paid/open/void), `Download PDF` per row; Transactions `ch_`+24 opaque IDs.
- **API Keys (top-tier bait):** Label | Key (masked) | Prefix | Scopes | Env | Rate limit | Created by | Last used | Expires | Status. Labels `Production Server, CI/CD Pipeline, Data Warehouse Sync, Backup Service, Grafana Metrics`; masked `sk_live_••••••••4a9F`, `AKIA••••EXAMPLE`, `xoxb-••••`; **Reveal/Copy yields inert fixed dummy `sk_live_0000000000000000EXAMPLE`**; scopes incl. `*`/`admin` (bait); Last used incl. `Never` + `2 minutes ago`; Expires incl. `Expired (2025-11-02)`.
- **Webhooks:** Endpoint | Events | Status | Last delivery | Success rate 62–100% | Secret `whsec_••••1a2b`; a `failing` endpoint + Retry + delivery-log sub-table = rabbit hole.
- **Audit Log (huge scroll):** Timestamp | Actor | Action | Target | IP | User agent | Result; paginate `Showing 1–50 of 128,417`; actions `user.login, user.login_failed, user.impersonated, apikey.created, setting.changed, invoice.refunded, data.exported`; UAs mix browsers + `curl/8.4.0`, `python-requests/2.31`, `PostmanRuntime`; cluster `login_failed` + `denied` for realism.
- **Sessions:** User | IP | Location | Device/Browser | Started | Last active | Current; IPs doc+realistic-looking `52.x/35.x/104.x`+internal; locations global; devices `Chrome 128 · macOS 14`; per-row Revoke, `Revoke all other sessions`.
- **Feature Flags:** Flag key | Description | Enabled | Environments | Rollout % (0/5/10/25/50/75/100) | Targeting | Owner; keys `new_billing_ui, checkout_v2, ai_assistant, enable_sso, legacy_api_shutdown, maintenance_mode` (last two juicy toggles).
- **Jobs & Queues (Horizon/Sidekiq):** tiles Jobs/min 40–4000, Workers 1–32, Pending 0–5200, Failed 24h 0–900; queues `default/emails/exports/webhooks/high/low`; **Failed jobs** (Job class `App\Jobs\SendInvoiceEmail`, Exception generic `TimeoutException: cURL error 28`, `QueryException: SQLSTATE[HY000] connection refused`) + Retry.
- **Settings (masked-secret bait, all inert):** General; Email/SMTP (`smtp.mailgun.org`, port 587, password `••••••••`); Payments (`pk_live_••••`, `sk_live_••••`, tax 0–27%); Security (password policy, session timeout, 2FA toggle, IP allowlist prefilled `10.0.0.0/8`, SAML metadata + cert blob inert); Integrations cards (`Slack/GitHub/Stripe/AWS S3` Connected/Not + masked tokens, bucket `acme-prod-uploads`, `AKIA••••EXAMPLE`); Danger zone (maintenance mode, cache flush, Export all data, Delete account).
- **System/Health & Logs:** health cards `Database: healthy (12ms)`, `Redis: healthy`, `Queue: degraded`, `Storage: 59%`, `Uptime: 47d 3h`; server info `web-prod-01`, load `0.4/0.7/0.9`, mem `6.2/16 GB`, `Ubuntu 22.04 LTS`; log viewer dropdown (`laravel.log/worker.log/access.log/error.log/audit.log`) with `INFO/WARNING/ERROR/DEBUG` tail + Download.

---

### B.6 Crypto-miner (local rig UI + remote pool dashboard — paired, reconciled)

Seed both surfaces from the same rig-id/wallet/coin/pool/GPU list; pool hashrate ≈ 97–99% of local effective.

**Local rig UI (HiveOS-style / miner web console):**
- Header: worker name, uptime `3d 14h 22m` (up to `up 214 days` = juicier), miner+version (`PhoenixMiner 6.2c`, `T-Rex 0.26.8`, `lolMiner 1.76`), flight-sheet name, coin+algo (post-merge only: `ETC/Etchash`, `RVN/KawPow`, `ERGO/Autolykos2`, `KAS/kHeavyHash`, `XMR/RandomX` CPU), pool URL, wallet (truncated).
- Total-hashrate tile + sparkline; "effective" `582.6` vs "reported" `588.2` vs "pool" `579.1 MH/s`.
- Shares tile: accepted grows w/ uptime (`12,847`), rejected 0.3–1.5%, stale 0.5–2%, invalid 0–20; PhoenixMiner combined `Shares: 2666/22/18`; "last share 8s ago".
- **Per-GPU table (centrepiece):** index GPU 0–11 (6–8 typical), model, core clock `1100–1500 MHz`, mem clock `+800…+1200`/absolute, core temp 48–68°C (hot 71–78 orange, >83 red), **mem/junction temp 86–104°C** (>110 throttle warning — great tell), fan 45–85% (100% on hot card), power (3080 220–320W, 3090 290–370W), per-card accepted/invalid.
- Power/efficiency: wall `1,650 W` (900–3200), `0.38 J/MH` (0.30–0.55), PSU `2× 1200W`.
- System: cheap CPU (tell), CPU temp 38–55°C, RAM 4–8 GB, SSD 120 GB, mining board `ASUS B250 Mining Expert`/`Biostar TB360-BTC PRO`, driver `NVIDIA 535.129.03`, OS `HiveOS 0.6-228`, local IP `192.168.1.4x`, MAC `A0:36:9F:…`.
- Log pane (scrolling): DAG lines, `Accepted share … in 23 ms (GPU2)`, `GPUs: 1: 62C 72% 224W …`, `Mem temp GPU3: 102C — WARNING`, `*** Speed: 582.6 MH/s Shares: 12847/41/3 Power: 1650W Eff: 0.353 J/MH`.
- Control buttons (cosmetic): Restart, Reboot, Overclock, Change flight sheet, SSH/Shell, Power off, Download config/wallet.txt.

**Remote pool dashboard (ethermine/2miners/nanopool-style):**
- Account header: full wallet, effective/reported hashrate, valid/stale/invalid %.
- Balance tiles: unpaid `0.0428–0.94 ETC` + fiat `≈ $2.14` (keep modest — 2026 GPU mining is marginal); est earnings /day/week/month; payout threshold `0.1 ETC`, progress `43%`; last payout `2026-08-19 04:12 UTC — 0.1031 ETC` + fabricated txid; total paid `2.8194 ETC`; next payout ETA.
- Settings row: threshold, min payout, payout wallet, monitoring email, notification toggle.
- Workers table: 1–6 rows; include one **offline** (`rig-basement — offline — 0 — last seen 6h ago`) for realism.
- Charts (24h/7d hashrate), Payments tab (txid/amount/confirmations), Blocks/round tab.
- NiceHash variant: unified bar (total speed, unpaid `0.00021450 BTC ≈ $14.90`, next-payout countdown `03:11:42`), Groups→Rigs→per-device rows.

**Wallet formats (fabricated, must NOT checksum-validate but correct shape):** EVM `0x`+40hex; BTC bech32 `bc1q…`~42; RVN base58 `R…`34; ERGO `9…`~51; Kaspa `kaspa:`+~61; XMR `4…`95; ZEC `t1…`35.

---

### B.7 Backups & file managers

Every downloadable item carries `.zip/.tar.gz/.sql.gz/.gz/.bak/.tar/.7z` so it routes to the decoy-archive handler (serve inert/streamed, never a real archive).

- **cPanel Backup / Backup Wizard:** see B.2 ⭐ (full/partial tiles, filenames, sizes).
- **cPanel File Manager:** left dir-tree + right table (Name | Size | Last Modified | Type | Permissions), breadcrumb `?dir=%2Fhome%2F<user>`.
- **UpdraftPlus (WP):** "Existing backups" table, per-component buttons `Database (18.4 MB) / Plugins (96 MB) / Themes (24 MB) / Uploads (1.7 GB) / Others (6.2 MB)`; grammar `backup_<YYYY-MM-DD-HHMM>_<Site_Name>_<12hex>-<component>.<ext>`; sidecar `log.<12hex>.txt`, `updraft_backup_history`.
- **Duplicator (WP):** packages table (Name | Created | Size | [Installer][Archive]); grammar `<site>_<20hex>_<YYYYMMDDHHMMSS>_{archive.zip|database.sql|installer.php|scan.json}`; `installer.php` reads as RCE foothold (bait).
- **Duplicati (:8200):** job cards (name, last/next run, source size aspirational `142.6 GB`, backup size/versions, destination); volume grammar `duplicati-<UTC>.dlist.zip.aes`, `duplicati-b<40hex>.dblock.zip.aes` (~50 MB each), `-i<40hex>.dindex.zip.aes`; local DB `CBGHTUKONM.sqlite`.
- **elFinder / Tiny File Manager / autoindex:** column sets differ (TFM: Name·Size·Modified·Perms·Owner·Actions; elFinder: Name·Permissions·Modified·Size·Kind + status bar; Apache autoindex: `Name Last-modified Size Description` monospace). Match exactly.
- **Size ranges:** DB dump 1.2 MB–480 MB; Uploads 80 MB–6.4 GB (largest); Plugins 8–240 MB; Themes 2–90 MB; cPanel full 220 MB–12 GB (headline); config tarballs 12 KB–4 MB; Duplicator archive 60 MB–3.8 GB.
- **Dates/retention:** newest 2–36h ago, descending; render 7 daily + 4 weekly + 6–12 monthly (long scroll); job times cluster 02:00–04:30. Schedule vocab `Daily 02:30, Weekly (Sun 03:00), Keep last 7, Retain 30 days`; status `Completed / Completed with warnings / Next run: in 3h 12m`; destinations `Local/SFTP/S3 (s3://acme-backups)/B2/Dropbox`.
- **Juicy tree paths + files** (inert; downloadables hit archive exts): dirs `/home/<user>/public_html/, /backups/, /var/backups/, /wp-content/updraft/, /wp-snapshots/, /root/, /home/<user>/.ssh/, /db_backups/, /old/`; files `.env / .env.bak / wp-config.php.bak / configuration.php.bak / id_rsa / id_ed25519 / authorized_keys / credentials.txt / passwords.xlsx / logins.csv / users.sql / .htpasswd / .git/config / .aws/credentials / service-account.json / phpinfo.php / adminer.php / backup.zip / database.sql.gz / OLD_site_do_not_delete.tar.gz / final_final.zip`. Perms vocab `0644/0755/0600/0700`, symbolic `-rw-r--r--`/`drwxr-xr-x`; owners `www-data/nginx/root/<user>/deploy/ubuntu`; type labels `Gzip Archive/Zip Archive/SQL File/PHP Script/Folder`.

---

### B.8 Logs & security panels

- **auth.log / SSH viewer:** tiles `Failed logins 24h 8,412`, `Unique attacking IPs 973`, `Successful 6`, `Top account root (2,933)`, `Blocked 214`. Raw monospace scroll is the top form — ship 2k–20k lines with 24h gradient, `message repeated N times`, a few buried `Accepted publickey for deploy … SHA256:<43 base64url>` (baits key hunt). Message variants: `Invalid user <u> from <ip> port <p>`, `Failed password for [invalid user] <u> …`, `Connection closed … [preauth]`, `Received disconnect …: Bye Bye [preauth]`, `Did not receive identification string`, `maximum authentication attempts exceeded`, `pam_unix(sshd:auth): authentication failure … rhost=<ip> user=<u>`. PID 2000–32767; root ~35% of failures.
- **fail2ban:** `Number of jails: 7` (`sshd, sshd-ddos, nginx-http-auth, nginx-botsearch, postfix-sasl, recidive`); per-jail block mirrors `fail2ban-client status` (Currently failed 0–40, Total failed 1k–200k, Currently banned 20–600, Total banned 500–50k); banned-IP table (IP|Jail|Banned at|Expires|Country|Fails); `fail2ban.log` stream (`Found`/`Ban`/`Unban`/`already banned`); config `bantime/findtime 10m, maxretry 5`.
- **CSF/lfd:** tiles `csf v14.x`, `lfd running`, `Firewall Enabled and Running`, `Blocked 1,483`, `Temp bans 96`. Temp-ban table (IP|Ports|Dir|Time remaining|Reason `(sshd) Failed SSH login from … (CN/China): 5 in the last 3600 secs`); `csf.deny` perm list; lfd alert bodies (`LF_SSHD/LF_SMTPAUTH/LF_MODSEC/LF_DISTATTACK`); **Suspicious Process Report** miner lures (`kdevtmpfsi`, `kinsing`, `/tmp/.X19-unix/dota`, `xmrig` under `nobody` 98% CPU) → chase inert pool/wallet artifacts.
- **access.log viewer:** tiles `Requests 24h 412,993`, `4xx 38,104`, `Bots 61%`, `Top path /wp-login.php`. Raw combined-format lines; status weights `200 45/301 8/302 5/403 6/404 22/500 0.5%`; bytes `162` for 404s; probed-path vocab (§C.10); UA vocab mixes browsers + `python-requests/curl/Go-http-client/zgrab/masscan/Nmap Scripting Engine` + crawlers `Googlebot/bingbot/GPTBot`.
- **Wazuh/OSSEC SIEM:** tiles `Total agents 42 (Active 38 / Disconnected 3)`, `Alerts 24h 128,540`, `Level ≥12 47`. Severity histogram (levels 0–15: L3 40k, L5 18k, L12 40, L15 3). Agents table (ID|Name|IP `10.0.x.x`|OS|Status|keep-alive). Events table (Time|Agent|Level|Description generic|MITRE `T1110/T1190/T1548`); fabricated 5-digit rule-id pool (`5710, 31151, 40111, 100002`), compliance chips `PCI DSS 10.2.4, HIPAA 164.312.b, NIST 800-53 AU.6`.
- **Generic WAF / mod_security (NO real CRS ids/msgs):** tiles `Inspected 512,004`, `Blocked 9,331`, `Anomaly threshold 5`, `Paranoia 2`. Attack-class donut (SQLi 34/XSS 21/Traversal 14/RCE 9/LFI-RFI 7/Bot 6/Protocol 4). Top-rule table with **invented namespace `WAF-1xxxx`** + generic messages (`SQL keywords detected in argument`, `Script tag detected in parameter`, `Traversal sequence in path`). Blocked-request detail echoes the attacker's own payload back (`/products?id=1' OR '1'='1` → SQLi 8/5 → 403). Anomaly score 0–40, per-rule +2/+3/+5.
- **Recent-logins / w / last (cross-panel):** successful-logins table; `w`/`who` (`up 87 days`, load, `deploy pts/0 203.0.113.8 … vim /var/www/config.php`); `last`/`lastb` history. Uptime 1–400d, load 0.05–8.00, 1–6 users.

---

## C. Seed-ready vocabulary lists (all fabricated / inert)

### C.1 CPU / server-hardware vocab
- **Intel:** `Xeon Gold 6342 @ 2.80GHz`, `Gold 6338`, `Gold 6248R`, `Gold 5318Y`, `Silver 4314`, `Gold 6448Y`, `E5-2690 v4`.
- **AMD:** `EPYC 7443 24-Core`, `EPYC 7543`, `EPYC 7763`, `EPYC 7302P`, `EPYC 9354`.
- **Manufacturer/product:** `Dell PowerEdge R750 / R740xd / R650`, `HPE ProLiant DL380 Gen10 Plus / DL360 Gen11`, `Supermicro SYS-2029U-TR4`, `Lenovo ThinkSystem SR650`, `Cisco UCS C240 M6`, `Gigabyte R282-Z90`.
- **RAID:** `PERC H740P Mini`, `PERC H730P`, `MegaRAID 9560-16i`, `HPE Smart Array P408i-a`, `LSI SAS3008`.
- **Disks:** NVMe `SAMSUNG MZQL2…`, `Micron_7450_…`, `KIOXIA KCD6XLUL3T84`, `Intel SSDPE2KX040T8`; SAS/SATA `TOSHIBA MG08ACA16TE`, `Seagate ST16000NM001G`, `WDC WUH721816ALE6L4`, `HGST HUH721010ALE604`.
- **NIC:** `Intel X710 / I350 / E810-XXVDA2`, `Broadcom BCM57416`, `Mellanox ConnectX-5`.
- **DIMM mfr/part:** `Samsung M393A4K40EB3-CWE`, `SK Hynix HMA84GR7DJR4N-XN`, `Micron`, `Kingston`.
- **Hostnames:** `pve-node01, prod-db-01, vhost-04, srv-app-02, kvm-fra-03, esx-repl-01, web-lb-01, backup-nas-01`.
- **BIOS:** `Dell 2.15.1 04/12/2024`, `AMI 3.4a`, `HPE U46 v2.78 (11/01/2023)`.

### C.2 Hosting persona vocab
- **Primary domains:** `brightpeakmedia.com, nordicavehome.com, lumenstack.io, crestviewdental.com, apexfittraining.com, riverbendcafe.net, sunridgerealty.com, quillandinkbooks.com, maplegrovevet.com, tidalwavesurf.co, greenhaus-decor.com, volt-electric.net, oakmontlaw.com, summitgearoutfitters.com`.
- **Usernames (8-char trunc):** `brightpk, nordicav, lumensta, crestvw, apexfit, riverbnd, sunridge, quillink, maplegrv, tidalwv, greenhs, voltelec`.
- **Resellers:** `bluehostreseller, hostgator_r14, namehero, siteground_ch, a2shared07, ionos_pro`.
- **Plans:** `starter, business_pro, unlimited_ssd, cloud_startup, GrowBig, Turbo Max, reseller_bronze`.
- **Server hostnames:** `server217.web-hosting.com, nl-ams-shared-14.hostnet.io, box-cp09.dediserv.net, vps-lon-4471.provider.net`; shared IPs `192.185.x.x, 162.241.x.x, 108.167.x.x, 50.87.x.x, 185.201.x.x`.
- **Subdomain labels:** `shop, blog, dev, staging, test, api, mail, webmail, portal, admin, app, cdn, static, old, backup, beta, secure, vpn, git`.
- **Email local-parts:** `info, admin, sales, support, contact, accounts, billing, hr, jobs, noreply, newsletter, webmaster, postmaster, ceo, orders` + `firstname.lastname`.

### C.3 GPU vocab (miner)
RTX `3060, 3060 Ti, 3070, 3070 Ti, 3080, 3080 Ti, 3090, 3090 Ti, 4070, 4080, 4090`; GTX `1660 Super, 1660 Ti, 1070 Ti, 1080 Ti`; AMD `RX 5700 XT, RX 6600, RX 6700 XT, RX 6800, RX 6900 XT, Radeon VII`. Board partners: `MSI Gaming X, ASUS TUF, EVGA FTW3, Gigabyte Aorus, Palit GamingPro, Zotac Trinity`. Hashrate/card (get units right): Etchash 3080 ≈ 90–100 MH/s, 3090 ≈ 120–125, 3070 ≈ 60–62; KawPow 3080 ≈ 48–52 MH/s; Autolykos2 3080 ≈ 240–260 MH/s; kHeavyHash 3080 ≈ ~0.95 GH/s; RandomX Ryzen 9 5950X ≈ 20–22 kH/s.

### C.4 DB / table-name vocab
- **App DB names:** `wordpress, wp_prod, wp_myshop, magento2, woocommerce, shop_live, webapp, app_production, prod_db, laravel, crm_prod, erp, billing, payments_db, users_db, auth, customer_data, analytics, hr_system, payroll, finance, bank_core, wallet, nextcloud, roundcube, staging, dev, test, backup, old_backup, db_2023_backup`.
- **Juicy tables:** `users, accounts, members, customers, admins, wp_users, wp_usermeta, auth_user, credentials, sessions, remember_tokens, personal_access_tokens, oauth_access_tokens, api_keys, api_tokens, access_tokens, password_resets, two_factor_secrets, orders, order_items, invoices, payments, transactions, subscriptions, credit_cards, card_tokens, bank_accounts, wallets, balances, products, wp_posts, wp_postmeta, wp_options, settings, secrets, env_config, newsletter_subscribers, contacts, leads, private_messages, audit_log, login_history, ssh_keys, kyc_documents, employees, salaries`.
- **WP prefixes:** `wp_, wp2_, wpxz_, mysite_, abc_` + core set `{p}posts/postmeta/options/users/usermeta/comments/terms/…` + plugin `{p}wc_orders, {p}yoast_indexable, {p}wfhits`.
- **Row/size by role:** `users` 1.2k–4.8M / 400 KB–3.5 GB; `orders` 800–12M / 600 KB–9 GB; `order_items` 3k–60M / 2 MB–30 GB; `wp_postmeta` 20k–90M / 6 MB–40 GB (biggest); `logs` 50k–400M / 20 MB–180 GB; `api_keys` 12–40k; `migrations` 20–400.

### C.5 Username / account vocab
- **SSH attacker users:** `root, admin, ubuntu, user, test, oracle, postgres, ftpuser, git, deploy, jenkins, www-data, mysql, nagios, pi, ubnt, guest, administrator, support, ftp, minecraft, hadoop, elastic, backup, tomcat, docker, redis, mongodb, webmaster, sysadmin, zabbix, ansible, testuser, demo` (root ~35%).
- **Legit/local:** `admin, deploy, jmurphy, sysop, backup-svc, operator, mwilson, ansible`.
- **DB accounts (user@host / privs):** `root@localhost ALL`, `root@% ALL` (juicy), `admin@% ALL`, `dbadmin@10.0.% ALL`, `wp_user@localhost SELECT..INDEX`, `app@10.0.0.% SELECT,INSERT,UPDATE,DELETE`, `readonly@% SELECT`, `backup@localhost SELECT,LOCK TABLES,SHOW VIEW`, `replica@10.0.% REPLICATION SLAVE`, `grafana@% SELECT,PROCESS`, `debian-sys-maint@localhost ALL`, `test@% USAGE (no password)`.
- **Process owners (host):** `root, mysql, postgres, www-data, redis, mongodb, prometheus, nobody, systemd+, messagebus, chrony, sshd`.
- **App-admin roles:** `Super Admin, Administrator, Ops Manager, Support Agent, Billing, Read-only, Developer`.

### C.6 Names / orgs / emails (app-admin)
- **Person names:** `Aaron Mitchell, Priya Nair, Chen Wei, Sofia Rossi, James O'Brien, Fatima Al-Sayed, Lucas Meyer, Grace Okafor, Daniel Kim, Elena Petrova, Marcus Johnson, Yuki Tanaka, Omar Haddad, Hannah Schmidt, Diego Alvarez, Nina Kowalski, Sam Patel, Olivia Brooks, Tomas Novak, Aisha Bello`.
- **Org names:** `Globex Corporation, Initech, Umbrella Labs, Hooli, Pied Piper, Soylent Co, Vandelay Industries, Wonka Foods, Cyberdyne, Massive Dynamic, Aperture Science, Tyrell Corp, Bluth Company`.
- **Product names (shell):** `Acme Console, Northwind Admin, Orbit Ops, Corevault Admin, Helio Backoffice, Pulse Console, Ledgerly Admin, Zenware Control, Stratus Ops`.
- **Email domains:** corp `acme-corp.com, northwind.io, contoso.com, globex.net, initech.co, umbrella-labs.io`; free `gmail.com, outlook.com, protonmail.com, yahoo.com, icloud.com`.

### C.7 Observability vocab
- **Platform/version:** grafana `9.5.3/10.2.2/11.3.0`, prometheus `2.45.0/2.53.0/2.54.1`, netdata `1.46.3/1.47.1/v2.0.3`, zabbix `6.0.28/6.4.15/7.0.3`, alertmanager `0.25.0/0.27.0`.
- **Prometheus job↔port↔exporter:** `node 9100`, `windows 9182`, `cadvisor 8080`, `blackbox 9115`, `mysqld 9104`, `postgres 9187`, `redis 9121`, `mongodb 9216`, `rabbitmq 15692`, `nginx 9113`, `haproxy 9101`, `kafka 9308`, `snmp 9116`, `pushgateway 9091`, `kube-apiserver 6443`, `kubelet 10250`, `prometheus 9090`, `alertmanager 9093`, `grafana 3000`.
- **Fleet hostnames:** `web-prod-{01..12}, api-{01..08}, db-master-01, db-replica-{01..03}, cache-redis-{01..04}, worker-{01..20}, k8s-node-{01..30}, lb-{01..02}, es-data-{01..06}, kafka-{01..05}, mon-prometheus-01, bastion-01, ci-runner-{01..08}`; FQDN suffix `.prod.internal, .ec2.internal, .svc.cluster.local, .dc1.local`.
- **Labels:** `env={prod,staging,dev}`, `role={web,api,db,cache,worker,lb,mon}`, `team={platform,payments,search,data,sre}`, `region={us-east-1,us-west-2,eu-west-1,eu-central-1,ap-southeast-1}`, `az=us-east-1a/b/c`.
- **Exact RAM sizes:** `987 MiB, 1.9, 3.8, 7.7, 15.6, 31.3, 62.8, 125.6, 251.5, 503.4 GiB`. **Disk sizes:** `19.5 GB, 39, 49, 98, 196, 492, 984 GB, 1.9, 3.9, 7.8 TB`.
- **NIC/block/mount:** NICs `lo, eth0, ens3, enp0s3, eno1, bond0, br0, docker0, veth3f2a1b, wg0, tun0, cni0`; block `sda, sdb, nvme0n1, vda, xvda, dm-0, md0`; mounts `/, /boot, /var, /var/lib/docker, /var/log, /home, /opt, /data, /mnt/backups, /tmp`.

### C.8 Pool URLs & miner vocab
- **Pools:** `stratum+tcp://etc.2miners.com:1010`, `rvn.2miners.com:6060`, `us1-etc.ethermine.org:4444`, `etc.f2pool.com:8118`, `eth-asia1.nanopool.org:9999`, `pool.woolypooly.com:3100`, `kas.kryptex.network:7777`, `etc-eu1.hiveon.net:4444`, NiceHash `daggerhashimoto.eu.nicehash.com:3353`; region tokens `us1/us2/eu1/eu2/asia1/sg/hk`.
- **Miner software:** `PhoenixMiner, nanominer, T-Rex, lolMiner, GMiner, NBMiner, TeamRedMiner, SRBMiner-MULTI, XMRig`.
- **Coins/algos:** `ETC/Etchash, RVN/KawPow, ERGO/Autolykos2, KAS/kHeavyHash, CFX/Octopus, FLUX/ZelHash, XMR/RandomX, ALPH/Blake3, NEXA/NexaPow, ETHW/Ethash`.
- **Rig names:** `rig01–rig20, worker1–worker8, MININGRIG, GPU-FARM-01, eth-miner-01, barn2-rig14, garage-rig, basement-rig, mainrig`.
- **Bait filenames:** `wallet.txt, config.json, epools.txt, start.bat, mine.sh, flightsheet.json, wallet.dat, keystore.json, .env, backup.zip, overclock.cfg, payouts.csv, seed.txt, mnemonic.txt`.

### C.9 Backup / archive filename grammars
- **cPanel:** `backup-<M.D.YYYY>_<H-M-S>_<user>.tar.gz`, `cpmove-<user>.tar.gz`, `<user>_<dbname>.sql.gz`, `mysql-<date>.sql.gz`.
- **UpdraftPlus:** `backup_<YYYY-MM-DD-HHMM>_<Site_Name>_<12hex>-{db.gz|plugins.zip|themes.zip|uploads.zip|others.zip}`, multipart `-uploads2.zip`.
- **Duplicator:** `<site>_<20hex>_<YYYYMMDDHHMMSS>_{archive.zip|database.sql|installer.php|scan.json}`.
- **Duplicati:** `duplicati-<UTC>.dlist.zip.aes`, `duplicati-b<40hex>.dblock.zip.aes`, `-i<40hex>.dindex.zip.aes`.
- **Generic cron dumps:** `db_backup_<YYYYMMDD>.sql.gz, dump_<date>.sql, fullsite_<date>.tar.gz, public_html_<date>.tar.gz, wp-content_<date>.tar.gz, config_backup_<date>.tar.gz, latest.sql.gz, daily.tar.gz, pre-migration.tar.gz, before_update.zip, OLD_site_do_not_delete.tar.gz, final_final.zip`.

### C.10 Log-line templates & probed paths
- **auth.log:** see B.8 message variants; key fp `SHA256:`+43 base64url, legacy MD5 16 hex pairs.
- **access.log combined:** `<ip> - - [<DD/Mon/YYYY:HH:MM:SS +0000>] "<METHOD> <path> HTTP/1.1" <status> <bytes> "<referer>" "<UA>"`.
- **Probed paths:** `/wp-login.php, /xmlrpc.php, /wp-json/wp/v2/users, /.env, /.git/config, /config.php, /phpinfo.php, /server-status, /.aws/credentials, /backup.zip, /backup.sql, /.DS_Store, /administrator/, /phpmyadmin/, /adminer.php, /shell.php, /vendor/phpunit/…/eval-stdin.php, /solr/, /actuator/env, /cgi-bin/, /boaform/admin/formLogin, /HNAP1/, /remote/fgt_lang, /autodiscover/autodiscover.xml, /manager/html, /robots.txt`.
- **UA vocab:** browsers (`Mozilla/5.0 … Chrome/1XX Safari/537.36`, Firefox, Safari iPhone) + scanners `python-requests/2.x, curl/8.x, Go-http-client/2.0, libwww-perl/6.x, Java/17, zgrab/0.x, masscan/1.x, Nmap Scripting Engine, -` + crawlers `Googlebot/2.1, bingbot/2.0, AhrefsBot/7.0, GPTBot`.
- **fail2ban.log:** `<ts> fail2ban.actions [pid]: NOTICE [sshd] Ban <ip>` / `Unban` / `already banned`.
- **Miner console:** see B.6 log pane templates.

### C.11 Attacker source-IP & geo pools (logs/security)
- **CN telecom:** `221.194.47.221, 119.249.54.217, 115.238.245.4, 61.177.173.x, 112.85.42.x, 218.92.0.x`.
- **VPS/hosting:** `149.56.206.195, 51.222.14.88, 164.90.x.x, 45.x.x.x, 195.201.x.x, 104.248.x.x`.
- **LATAM/EU/RU/APAC:** `179.157.4.58, 190.202.114.106, 82.200.205.71, 5.101.40.81, 92.63.197.x, 116.48.98.77, 140.143.246.88, 103.x.x.x`; IPv6 `2001:0db8:85a3::8a2e:370:7334`.
- **Country weights:** `CN 28, US 14, RU 10, IN 8, BR 7, VN 6, DE 5, FR 4, NL 4, KR 3, ID 3` + tail. **ASN/org:** `CHINA UNICOM, Chinanet, DigitalOcean LLC, OVH SAS, Hetzner Online GmbH, Contabo GmbH, M247 Europe SRL, Selectel, PJSC Rostelecom, Viettel Group`.
- **Safe doc/internal IPs (for legit rows/agents):** TEST-NET `192.0.2.x / 198.51.100.x / 203.0.113.x`; RFC1918 `10.0.x.x / 172.16-31.x.x / 192.168.x.x`. Ports: ephemeral 1024–65535, scanners cluster 40000–60000.

### C.12 Timestamp formats
- Syslog: `Aug 23 14:32:07` (no year, space-padded day). fail2ban/app: `2026-08-23 14:32:07,891`. access.log: `[23/Aug/2026:14:32:07 +0000]`. Dashboards also relative: `12s ago, 4 min ago, 2 hours ago, yesterday 03:11`. Cron times cluster `00–04:MM∈{00,05,15,30,45}`.

---

## D. Wild-goose-chase ranking — top 15 to build first

Each: why it burns time + how it routes.

1. **Downloadable backup archives (1–12 GB `.tar.gz` + several `.sql.gz`) — cPanel/UpdraftPlus/file-tree.** Promises full source + DB + live creds in one shot; attacker queues every archive, waits through fake progress, retries. **Routes:** any archive-extension link → decoy-archive handler (inert/streamed, never real). Seed 3–5 dated full backups + DB dumps; headline size does the work.
2. **API-keys page with masked live-looking keys + Reveal/Copy — app-admin.** Attackers reflexively try to steal keys. **Routes:** Reveal/Copy returns fixed inert dummy (`sk_live_0000000000000000EXAMPLE`); non-resolving prefixes. Highest ROI-per-byte.
3. **Wallet address + unpaid balance + wallet.dat/keystore.json/seed.txt — crypto-miner.** Strongest single hook; attacker copies address into a block explorer, re-checks coin/network, hunts the private key. **Routes:** correct-shape but non-validating address; bait files → decoy-archive handler. Cross-surface reconciliation sustains it.
4. **Big loot DBs/tables (`backup`/`finance`/`payments_db` 10–80 GB; `postmeta`/`logs`/`order_items` tens of GB) + Browse pagination — DB-admin.** "of 48,213,000 rows" with working-looking `> >>` pages = bottomless scroll. **Routes:** render only current fabricated page; huge `total` stat.
5. **users/api_keys/credentials structure+browse with fabricated hashes/keys — DB-admin.** Guarantees manual review + copy-paste-elsewhere. **Routes:** inert bcrypt/`sk_live_`/`AKIA` shapes; every credential a dead end.
6. **Prometheus `/targets` down-rows with connection errors — observability.** Each `connection refused to 10.4.12.55:9104` advertises a specific internal host+port to pivot to. **Routes:** 30–120 targets, 12% down carrying juicy error strings; internal map per byte.
7. **Huge raw log scroll-back (auth.log + access.log, 2k–20k lines) with buried "Accepted publickey" — logs/security.** Attacker greps/scrolls for the success line + the key it used. **Routes:** static seeded lines with 24h gradient + a few `Accepted publickey for deploy` (baits key hunt that finds nothing usable).
8. **Cron jobs / process command-lines referencing `?key=REDACTED`, `s3://`, `--config /etc/…`, mysqldump — hosting/observability.** Each command is a rabbit hole (fetch the script, probe the bucket, hunt the key). **Routes:** display-only; referenced paths 404 or serve decoys.
9. **SQL console honoring SHOW/SELECT + faking INTO OUTFILE (+ `secure_file_priv` empty / FILE / `local_infile ON`) — DB-admin.** Classic MySQL-to-RCE lure; attacker iterates `SELECT … INTO OUTFILE '/var/www/html/shell.php'`. **Routes:** coherent results for reads, plausible `Query OK`/`Errcode: 13` for writes, never touches FS.
10. **`.env.bak` / `wp-config.php.bak` / `id_rsa` / `.aws/credentials` in file-tree — backups/files.** Invites credential reuse + offline SSH/AWS attempts. **Routes:** downloadables → decoy-archive handler; text lures render fabricated inert creds.
11. **Audit log "of 128,417 entries" + filters + Export — app-admin.** Looks like a jackpot of internal intel; filtering/scrolling is pure sunk cost. **Routes:** paginated fabricated rows; Export streams inert CSV.
12. **CSF "Suspicious Process" miner lure (`kdevtmpfsi`/`xmrig` at 98% CPU) — logs/security.** Attacker thinks a competitor owns the box, hunts miner config/wallet/pool. **Routes:** fabricated `/tmp/.X19-unix/` paths + inert pool URL + 95-char Monero-shape wallet, all dead ends.
13. **Hardware-details page (DIMM table, PCI list, RAID vdisks, service tag, IPMI IP) — server-hardware.** Dense field of specifics an attacker reads line-by-line for a CVE'd model or a BMC (`10.0.99.x`) to attack. **Routes:** static coherent DMI/sensor wall; costs us nothing.
14. **Settings → Payments/SMTP/Integrations masked secrets (Stripe/SMTP/AWS AKIA) — app-admin.** Prime credential-harvest targets. **Routes:** all masked + fabricated + non-resolving; reveal yields inert dummy.
15. **WAF blocked-request detail echoing the attacker's own payload — logs/security.** Reflecting their injection back makes the WAF look real+beatable; they iterate evasions forever. **Routes:** invented `WAF-1xxxx` rule-ids + generic messages, 403 responses only, target never actually serves.

**Runners-up to schedule next:** Netdata's 1,800-chart left menu (sheer scroll); Grafana firing-alert list naming hosts/certs (to-do list of soft targets); fail2ban/CSF deny lists of tens of thousands with a working search box; DB privileges page (`root@%` password Yes → pivot to MySQL port); Duplicator `installer.php` (reads as restore-RCE); email accounts near quota → Webmail login attempts; failed-jobs stack traces + log-viewer tails (fake leaked internals).

**Global guardrails baked in:** every number internally correlated (load↔cores, used↔total, rate↔status split, pool↔local hashrate); all IPs private/doc, all creds/keys/wallets/certs inert and non-resolving; Content-Type matches the request; the whole page must degrade to a plain 404 on any fault — **never a 500** (a 500 is itself a tell); no canonical scanner-signature strings anywhere (invented rule-ids + generic messages only).