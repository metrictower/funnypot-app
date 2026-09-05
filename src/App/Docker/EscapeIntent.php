<?php

declare(strict_types=1);

namespace Funnypot\App\Docker;

/**
 * Pure, INERT classifier for the container-deploy intent in a `POST /containers/create` (or
 * `/exec`) body. It reads the attacker's requested image, command, environment and HostConfig and
 * derives a bounded, structured intel record — the escape configuration (bind mounts, --privileged,
 * --pid=host, cap-add, …), a cryptojacking/dropper fingerprint, and a class + severity — WITHOUT
 * ever running, decoding-and-running, resolving, or unpacking any of it. Base64 in a command is
 * DETECTED as a signal; it is never decoded. Socket paths and hostnames are matched as strings; they
 * are never opened or contacted.
 *
 * Everything is bounded so a hostile 64 KB body cannot blow up the row: item counts and per-value
 * lengths are capped, the JSON decode is depth-limited, and fields are UTF-8-scrubbed so a non-UTF-8
 * image/cmd can never make the record silently unwritable downstream.
 *
 * The signal vocabulary is a FIXED token set (below) with no attacker bytes, so it can safely become
 * dashboard `templates` badges (bounded cardinality) and a trusted AbuseIPDB comment prefix.
 */
final class EscapeIntent
{
    // --- classes ---
    public const CLASS_ESCAPE = 'docker_escape';
    public const CLASS_API = 'docker_api';

    // --- bounded vocabulary: container-escape signals (host takeover primitives) ---
    public const ESCAPE_SIGNALS = [
        'bind-root', 'bind-sensitive', 'bind-docker-sock', 'privileged', 'pid-host', 'net-host',
        'ipc-host', 'userns-host', 'cap-sys-admin', 'seccomp-unconfined', 'apparmor-unconfined',
        'device-passthrough', 'chroot-host', 'cgroup-escape',
    ];

    // --- bounded vocabulary: payload signals (what the container would then do) ---
    public const PAYLOAD_SIGNALS = ['miner', 'dropper', 'persistence', 'cron-lateral'];

    // --- caps ---
    private const MAX_ITEMS = 16;
    private const MAX_ENV = 32;
    private const MAX_ITEM_LEN = 512;
    private const MAX_ENV_LEN = 256;
    private const MAX_STR = 64;
    private const MAX_JOINED = 2000;
    private const DECODE_DEPTH = 8;

    /** Docker socket paths — matched as strings for the bind-docker-sock signal, never opened. */
    private const SOCK_PATHS = ['/var/run/docker.sock', '/run/docker.sock', '/run/containerd/containerd.sock'];

    /** Host paths whose bind-mount is a strong escape tell. */
    private const SENSITIVE_PREFIXES = ['/etc', '/root', '/home', '/proc', '/sys', '/dev', '/boot', '/var/lib/docker', '/mnt', '/var/run'];

    /**
     * @param string $registryTokenKey private install key for the captured-password correlation token;
     *        never the public persona seed, which an attacker could reproduce.
     */
    public function __construct(private int $seed, private string $registryTokenKey)
    {
    }

    /**
     * Classify a `/containers/create` body.
     *
     * @param array<mixed>        $body    the JSON-decoded create body (already depth-capped by caller, or re-cap here)
     * @param string              $query   the raw query string (?name=…) captured verbatim
     * @param array<string,string> $headers request headers (for X-Registry-Auth)
     * @return array<string,mixed> the bounded structured intel record
     */
    public function fromCreate(array $body, string $query = '', array $headers = []): array
    {
        $host = is_array($body['HostConfig'] ?? null) ? $body['HostConfig'] : [];

        $image = $this->str($body['Image'] ?? '', 255);
        $ref = ImageRef::parse($image);
        $entrypoint = $this->wordList($body['Entrypoint'] ?? null);
        $cmd = $this->wordList($body['Cmd'] ?? null);
        $env = $this->stringList($body['Env'] ?? null, self::MAX_ENV, self::MAX_ENV_LEN);
        $binds = $this->stringList($host['Binds'] ?? null, self::MAX_ITEMS, self::MAX_ITEM_LEN);
        $mounts = $this->mounts($host['Mounts'] ?? null);
        $volumes = $this->mapKeys($body['Volumes'] ?? null);
        $capAdd = $this->stringList($host['CapAdd'] ?? null, self::MAX_ITEMS, self::MAX_STR);
        $capDrop = $this->stringList($host['CapDrop'] ?? null, self::MAX_ITEMS, self::MAX_STR);
        $securityOpt = $this->stringList($host['SecurityOpt'] ?? null, self::MAX_ITEMS, self::MAX_ITEM_LEN);
        $devices = $this->devices($host['Devices'] ?? null);

        $record = [
            'image' => $image,
            'image_ref' => [
                'registry' => $ref['registry'], 'repo' => $ref['repo'],
                'tag' => $ref['tag'], 'digest' => $ref['digest'], 'display' => $ref['display'],
            ],
            'entrypoint' => $entrypoint,
            'cmd' => $cmd,
            'command' => $this->str(implode(' ', array_merge($entrypoint, $cmd)), self::MAX_JOINED),
            'env' => $env,
            'user' => $this->str($body['User'] ?? '', self::MAX_STR),
            'working_dir' => $this->str($body['WorkingDir'] ?? '', self::MAX_ITEM_LEN),
            'hostname' => $this->str($body['Hostname'] ?? '', self::MAX_STR),
            'tty' => (bool) ($body['Tty'] ?? false),
            'open_stdin' => (bool) ($body['OpenStdin'] ?? false),
            'labels' => $this->mapKeys($body['Labels'] ?? null),
            'binds' => $binds,
            'mounts' => $mounts,
            'volumes' => $volumes,
            'privileged' => (bool) ($host['Privileged'] ?? false),
            'pid_mode' => $this->str($host['PidMode'] ?? '', self::MAX_STR),
            'network_mode' => $this->str($host['NetworkMode'] ?? '', self::MAX_STR),
            'ipc_mode' => $this->str($host['IpcMode'] ?? '', self::MAX_STR),
            'uts_mode' => $this->str($host['UTSMode'] ?? '', self::MAX_STR),
            'userns_mode' => $this->str($host['UsernsMode'] ?? '', self::MAX_STR),
            'cgroupns_mode' => $this->str($host['CgroupnsMode'] ?? '', self::MAX_STR),
            'cgroup_parent' => $this->str($host['CgroupParent'] ?? '', self::MAX_ITEM_LEN),
            'runtime' => $this->str($host['Runtime'] ?? '', self::MAX_STR),
            'cap_add' => $capAdd,
            'cap_drop' => $capDrop,
            'security_opt' => $securityOpt,
            'devices' => $devices,
            'auto_remove' => (bool) ($host['AutoRemove'] ?? false),
            'restart_policy' => $this->str(
                is_array($host['RestartPolicy'] ?? null) ? ($host['RestartPolicy']['Name'] ?? '') : '',
                self::MAX_STR
            ),
            'name' => $this->nameFromQuery($query),
            'registry_auth' => $this->registryAuth($headers),
        ];

        $signals = $this->signals($record);
        $record['signals'] = $signals;
        $record['class'] = $this->classify($signals);

        return $record;
    }

    /**
     * Classify an `/exec` body — the second place the real command lands.
     *
     * @param array<mixed> $body
     * @return array<string,mixed>
     */
    public function fromExec(array $body): array
    {
        $cmd = $this->wordList($body['Cmd'] ?? null);
        $env = $this->stringList($body['Env'] ?? null, self::MAX_ENV, self::MAX_ENV_LEN);
        $record = [
            'cmd' => $cmd,
            'command' => $this->str(implode(' ', $cmd), self::MAX_JOINED),
            'env' => $env,
            'user' => $this->str($body['User'] ?? '', self::MAX_STR),
            'privileged' => (bool) ($body['Privileged'] ?? false),
            'tty' => (bool) ($body['Tty'] ?? false),
        ];
        $signals = $this->signals($record + ['image' => '', 'binds' => [], 'mounts' => [], 'cap_add' => [], 'security_opt' => [], 'devices' => [], 'pid_mode' => '', 'network_mode' => '', 'ipc_mode' => '', 'uts_mode' => '', 'userns_mode' => '', 'cgroup_parent' => '']);
        $record['signals'] = $signals;
        $record['class'] = $this->classify($signals);

        return $record;
    }

    /** Confidence funnypot attaches to the threat-intel report for this class + payload mix. */
    public static function confidenceFor(array $record): float
    {
        $signals = (array) ($record['signals'] ?? []);
        if (($record['class'] ?? '') === self::CLASS_ESCAPE) {
            return 0.95;
        }
        if (array_intersect($signals, self::PAYLOAD_SIGNALS) !== []) {
            return 0.9;
        }

        return 0.8;
    }

    /**
     * Depth-capped, bounded JSON decode of a create/exec body. Returns [] on anything that is not a
     * JSON object (a malformed body classifies as a plain, empty create — never an exception).
     *
     * @return array<mixed>
     */
    public static function decodeBody(?string $rawBody): array
    {
        $decoded = json_decode((string) $rawBody, true, self::DECODE_DEPTH);

        return is_array($decoded) ? $decoded : [];
    }

    // --- signal derivation (fixed tokens only) ---

    /**
     * @param array<string,mixed> $r
     * @return list<string>
     */
    private function signals(array $r): array
    {
        $out = [];
        $binds = (array) ($r['binds'] ?? []);
        $mounts = (array) ($r['mounts'] ?? []);

        // Bind / mount host sources.
        $sources = $binds;
        foreach ($mounts as $m) {
            if (is_array($m) && isset($m['source']) && is_string($m['source'])) {
                $sources[] = $m['source'];
            }
        }
        foreach ($sources as $src) {
            $hostPath = $this->bindHostPath((string) $src);
            if ($hostPath === '/') {
                $out[] = 'bind-root';
            }
            foreach (self::SOCK_PATHS as $sock) {
                if (strpos($hostPath, $sock) !== false || strpos((string) $src, $sock) !== false) {
                    $out[] = 'bind-docker-sock';
                }
            }
            foreach (self::SENSITIVE_PREFIXES as $pre) {
                if ($hostPath === $pre || strpos($hostPath, $pre . '/') === 0) {
                    $out[] = 'bind-sensitive';
                }
            }
        }

        if ($r['privileged'] ?? false) {
            $out[] = 'privileged';
        }
        if ($this->isHost($r['pid_mode'] ?? '')) {
            $out[] = 'pid-host';
        }
        if ($this->isHost($r['network_mode'] ?? '')) {
            $out[] = 'net-host';
        }
        if ($this->isHost($r['ipc_mode'] ?? '')) {
            $out[] = 'ipc-host';
        }
        if ($this->isHost($r['userns_mode'] ?? '')) {
            $out[] = 'userns-host';
        }
        if (($r['cgroup_parent'] ?? '') !== '') {
            $out[] = 'cgroup-escape';   // CVE-2022-0492 release_agent lane: a custom cgroup parent
        }

        $caps = array_map('strtoupper', (array) ($r['cap_add'] ?? []));
        foreach (['SYS_ADMIN', 'ALL', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH'] as $cap) {
            if (in_array($cap, $caps, true)) {
                $out[] = 'cap-sys-admin';
                break;
            }
        }

        $secopt = strtolower(implode(' ', (array) ($r['security_opt'] ?? [])));
        if (strpos($secopt, 'seccomp=unconfined') !== false || strpos($secopt, 'seccomp:unconfined') !== false) {
            $out[] = 'seccomp-unconfined';
        }
        if (strpos($secopt, 'apparmor=unconfined') !== false || strpos($secopt, 'apparmor:unconfined') !== false) {
            $out[] = 'apparmor-unconfined';
        }

        foreach ((array) ($r['devices'] ?? []) as $dev) {
            if (preg_match('#^/dev/(mem|kmsg|sd[a-z]|nvme\d)#', (string) $dev) === 1) {
                $out[] = 'device-passthrough';
                break;
            }
        }

        // Payload fingerprints over image + command + env (string matching only; never executed).
        $hay = strtolower(trim(
            (string) ($r['image'] ?? '') . ' ' . (string) ($r['command'] ?? '') . ' ' . implode(' ', (array) ($r['env'] ?? []))
        ));
        $rawHay = trim((string) ($r['command'] ?? '') . ' ' . implode(' ', (array) ($r['env'] ?? [])));

        if (strpos($hay, 'chroot /host') !== false || strpos($hay, 'nsenter -t 1') !== false
            || strpos($hay, 'nsenter --target 1') !== false || strpos($hay, '/proc/1/ns') !== false) {
            $out[] = 'chroot-host';
        }
        if (preg_match('~xmrig|minerd|cpuminer|nanominer|t-rex|lolminer|nbminer|kdevtmpfsi|kinsing|stratum\+tcp|--donate-level|-o\s+\S+:(?:3333|4444|5555|7777|14444)~', $hay) === 1
            || preg_match('~\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b~', $rawHay) === 1) {
            $out[] = 'miner';
        }
        if (preg_match('~(?:curl|wget)\b[^|]*\|\s*(?:sh|bash)~', $hay) === 1
            || strpos($hay, 'base64 -d') !== false || strpos($hay, '/dev/tcp/') !== false
            || preg_match('~\bbash\s+-i\b~', $hay) === 1 || preg_match('~\bnc\s+-e\b|\bncat\b|\bsocat\b~', $hay) === 1
            || strpos($hay, "python -c 'import socket") !== false) {
            $out[] = 'dropper';
        }
        if (strpos($hay, 'crontab') !== false || strpos($hay, 'authorized_keys') !== false
            || strpos($hay, '/etc/rc.local') !== false || strpos($hay, 'systemctl enable') !== false) {
            $out[] = 'persistence';
        }
        if (preg_match('~\b(?:masscan|zgrep|pnscan|zmap)\b~', $hay) === 1) {
            $out[] = 'cron-lateral';
        }

        return array_values(array_unique($out));
    }

    /** @param list<string> $signals */
    private function classify(array $signals): string
    {
        return array_intersect($signals, self::ESCAPE_SIGNALS) !== [] ? self::CLASS_ESCAPE : self::CLASS_API;
    }

    // --- bounded extractors ---

    private function bindHostPath(string $bind): string
    {
        // `Binds` entries are host:container[:opts]; the host source is the first component. A bare
        // Windows path or a named volume has no leading `/`, so only a leading-slash source counts.
        if ($bind === '') {
            return '';
        }
        if ($bind[0] === '/') {
            $colon = strpos($bind, ':');

            return $colon === false ? $bind : substr($bind, 0, $colon);
        }

        return '';
    }

    /** @param mixed $v */
    private function isHost($v): bool
    {
        return is_string($v) && strtolower($v) === 'host';
    }

    /** @param mixed $v @return list<string> a Cmd/Entrypoint may be a string or a string array. */
    private function wordList($v): array
    {
        if (is_string($v)) {
            $v = [$v];
        }
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $item) {
            if (count($out) >= self::MAX_ITEMS) {
                break;
            }
            if (is_scalar($item)) {
                $out[] = $this->str((string) $item, self::MAX_ITEM_LEN);
            }
        }

        return $out;
    }

    /** @param mixed $v @return list<string> */
    private function stringList($v, int $maxItems, int $maxLen): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $item) {
            if (count($out) >= $maxItems) {
                break;
            }
            if (is_scalar($item)) {
                $out[] = $this->str((string) $item, $maxLen);
            }
        }

        return $out;
    }

    /** @param mixed $v @return list<array{type:string,source:string,target:string,read_only:bool}> */
    private function mounts($v): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $m) {
            if (count($out) >= self::MAX_ITEMS) {
                break;
            }
            if (!is_array($m)) {
                continue;
            }
            $out[] = [
                'type' => $this->str($m['Type'] ?? '', self::MAX_STR),
                'source' => $this->str($m['Source'] ?? '', self::MAX_ITEM_LEN),
                'target' => $this->str($m['Target'] ?? '', self::MAX_ITEM_LEN),
                'read_only' => (bool) ($m['ReadOnly'] ?? false),
            ];
        }

        return $out;
    }

    /** @param mixed $v @return list<string> device PathOnHost values */
    private function devices($v): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $d) {
            if (count($out) >= self::MAX_ITEMS) {
                break;
            }
            if (is_array($d) && isset($d['PathOnHost']) && is_scalar($d['PathOnHost'])) {
                $out[] = $this->str((string) $d['PathOnHost'], self::MAX_ITEM_LEN);
            } elseif (is_string($d)) {
                $out[] = $this->str($d, self::MAX_ITEM_LEN);
            }
        }

        return $out;
    }

    /** @param mixed $v @return list<string> up to MAX_ITEMS map keys (labels/volumes: keys only) */
    private function mapKeys($v): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach (array_keys($v) as $k) {
            if (count($out) >= self::MAX_ITEMS) {
                break;
            }
            if (is_string($k)) {
                $out[] = $this->str($k, self::MAX_STR);
            }
        }

        return $out;
    }

    private function nameFromQuery(string $query): string
    {
        if ($query === '') {
            return '';
        }
        parse_str($query, $q);

        return isset($q['name']) && is_string($q['name']) ? $this->str($q['name'], 128) : '';
    }

    /**
     * Decode the base64 JSON `X-Registry-Auth` header into non-secret intel. The PASSWORD is NEVER
     * stored: it is reduced to a short seed-keyed HMAC token (a correlation handle, not a crackable
     * digest and not cleartext). An identity/registry token auth records only its presence.
     *
     * @param array<string,string> $headers
     * @return array<string,mixed>
     */
    private function registryAuth(array $headers): array
    {
        $raw = '';
        foreach ($headers as $k => $v) {
            if (strcasecmp($k, 'X-Registry-Auth') === 0) {
                $raw = (string) $v;
                break;
            }
        }
        if ($raw === '') {
            return [];
        }
        $json = base64_decode(strtr($raw, '-_', '+/'), false);
        if ($json === false || $json === '') {
            return ['present' => true, 'parsed' => false];
        }
        $auth = json_decode($json, true, self::DECODE_DEPTH);
        if (!is_array($auth)) {
            return ['present' => true, 'parsed' => false];
        }
        $out = [
            'present' => true,
            'parsed' => true,
            'username' => $this->str($auth['username'] ?? '', self::MAX_STR),
            'serveraddress' => $this->str($auth['serveraddress'] ?? '', self::MAX_ITEM_LEN),
            'has_identitytoken' => ($auth['identitytoken'] ?? '') !== '' || ($auth['registrytoken'] ?? '') !== '',
        ];
        $pw = $auth['password'] ?? '';
        if (is_string($pw) && $pw !== '') {
            // Keyed correlation token, 128 bits retained: same password ⇒ same token within one
            // install, unrecoverable and uncorrelatable across installs.
            $out['pw_token'] = substr(hash_hmac('sha256', 'fp-docker-registry-token|' . $pw, $this->registryTokenKey), 0, 32);
        }

        return $out;
    }

    /** Bound + UTF-8-scrub a value so a hostile non-UTF-8 byte can never make the record unwritable. */
    private function str($v, int $max): string
    {
        if (!is_scalar($v)) {
            return '';
        }
        $s = substr((string) $v, 0, $max);

        // Replace invalid UTF-8 sequences with U+FFFD so a later json_encode of the record cannot
        // fail (which would silently drop the whole phantom: a 201 create then a 404 start).
        return (string) mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    }
}
