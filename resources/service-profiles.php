<?php

declare(strict_types=1);

/**
 * The semantic layer over demo/ports.json: what each selectable service MEANS for a coherent persona.
 * It carries labels, family membership, dependencies, exclusions, process-unit counts, fixed probe
 * ids, start/stop deadlines and UDP safety classes — and it joins to the raw port inventory only by
 * stable endpoint ids. It contains NO copied port numbers, bind strings or commands: the tuple truth
 * stays in ports.json (Funnypot\App\Ops\PortManifest) and ServiceCatalog fails closed on any orphan.
 *
 * Selectable services are the process-backed listeners and media capabilities plus a curated subset
 * of nginx web aliases (the Docker Engine API surface and one alt-HTTP alias). Canonical web (80/443)
 * is always on and is never a selectable service. Every listener/media endpoint in ports.json has
 * exactly one owner here; the remaining nginx aliases stay static and are not profile-selectable.
 *
 * Family membership is SOFT: named/manual selection outside the chosen base family is a coherence
 * warning, never a rejection (an operator may deliberately mix), and `all` waives it entirely. Hard
 * rules — capability, dependency, exclusion, conflict-group variant, process ceiling and UDP safety —
 * are never waived.
 */

return [
    'schema' => 'funnypot-service-profiles/v1',

    // The closed base-family vocabulary. manual/all require one explicitly; named derives it.
    'base_families' => ['linux', 'windows', 'voip', 'ot', 'devops', 'neutral'],

    // The target process ceiling: the number of listener/media child processes the supervisor may run.
    // Equal to the current entrypoint instance count; growth past it fails catalog CI until reviewed.
    'process_ceiling' => 40,

    // Closed probe id -> the ServiceHealthProbeRegistry class handles the implementation.
    'probe_ids' => ['tcp-connect-v1', 'udp-echo-v1', 'sip-signalling-v1', 'media-reserved-v1', 'nginx-alias-v1'],

    // UDP safety classes (spec §11); a selectable UDP endpoint without one is unselectable in every mode.
    'udp_classes' => ['strict-datagram-v1', 'sip-cumulative-v1', 'return-routable-media-v1'],

    'services' => [
        // --- classic Unix / Linux listeners --------------------------------------------------------
        'ssh'        => ['label' => 'OpenSSH',            'families' => ['linux', 'devops', 'windows', 'ot', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['ssh-2222', 'ssh-alias-22']],
        'ftp'        => ['label' => 'FTP',                'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['ftp-21']],
        'telnet'     => ['label' => 'Telnet',             'families' => ['linux', 'ot', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['telnet-23']],
        'smtp'       => ['label' => 'SMTP',               'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['smtp-25']],
        'pop3'       => ['label' => 'POP3',               'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['pop3-110']],
        'imap'       => ['label' => 'IMAP',               'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['imap-143']],
        'finger'     => ['label' => 'finger',             'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['finger-79']],
        'rsync'      => ['label' => 'rsync',              'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['rsync-873']],
        'rtsp'       => ['label' => 'RTSP camera',        'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['rtsp-554']],
        'adb'        => ['label' => 'Android Debug Bridge', 'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['adb-5555']],
        'cwmp'       => ['label' => 'TR-069/CWMP',        'families' => ['linux', 'neutral'], 'process_units' => 2, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['cwmp-7547', 'cwmp-7548']],
        'vnc'        => ['label' => 'VNC',                'families' => ['linux', 'windows', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['vnc-5900', 'vnc-alias-5800', 'vnc-alias-5901', 'vnc-alias-5902']],

        // --- datastores / caches / brokers (linux + devops) ----------------------------------------
        'mysql'      => ['label' => 'MySQL',              'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['mysql-3306']],
        'postgresql' => ['label' => 'PostgreSQL',         'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['postgresql-5432']],
        'redis'      => ['label' => 'Redis',              'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['redis-6379']],
        'mongodb'    => ['label' => 'MongoDB',            'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['mongodb-27017']],
        'memcached'  => ['label' => 'memcached',          'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['memcached-11211']],
        'cassandra'  => ['label' => 'Cassandra',          'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['cassandra-9042']],
        'zookeeper'  => ['label' => 'ZooKeeper',          'families' => ['linux', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['zookeeper-2181']],
        'mqtt'       => ['label' => 'MQTT broker',        'families' => ['linux', 'devops', 'ot', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['mqtt-1883']],
        'clamav'     => ['label' => 'ClamAV',             'families' => ['linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['clamav-3310']],
        'oracle'     => ['label' => 'Oracle TNS',         'families' => ['linux', 'windows', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['oracle-1521']],

        // --- Windows / directory listeners ---------------------------------------------------------
        'smb'        => ['label' => 'SMB',                'families' => ['windows', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['smb-445']],
        'rdp'        => ['label' => 'RDP',                'families' => ['windows', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['rdp-3389']],
        'mssql'      => ['label' => 'MSSQL',              'families' => ['windows', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['mssql-1433']],
        'winrm'      => ['label' => 'WinRM',              'families' => ['windows', 'devops', 'neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['winrm-5985']],
        'kerberos'   => ['label' => 'Kerberos KDC',       'families' => ['windows'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['kerberos-88']],
        'ldap'       => ['label' => 'LDAP',               'families' => ['windows', 'linux'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['ldap-389']],

        // --- VoIP / PBX ----------------------------------------------------------------------------
        'sip'        => ['label' => 'SIP signalling',     'families' => ['voip', 'neutral'], 'process_units' => 1, 'probe_id' => 'sip-signalling-v1', 'udp_class' => 'sip-cumulative-v1', 'endpoint_ids' => ['sip-5060', 'sip-alias-5061', 'sip-alias-5080', 'sip-5060-udp', 'sip-alias-5061-udp', 'sip-alias-5080-udp']],
        'rtp'        => ['label' => 'RTP media',          'families' => ['voip'], 'process_units' => 0, 'probe_id' => 'media-reserved-v1', 'udp_class' => 'return-routable-media-v1', 'media_of' => 'sip', 'selectable' => false, 'endpoint_ids' => ['rtp-10000-udp']],
        'stun'       => ['label' => 'STUN',               'families' => ['voip', 'neutral'], 'process_units' => 1, 'probe_id' => 'udp-echo-v1', 'udp_class' => 'strict-datagram-v1', 'endpoint_ids' => ['stun-3478-udp']],

        // --- OT / ICS ------------------------------------------------------------------------------
        'modbus'      => ['label' => 'Modbus/TCP PLC',    'families' => ['ot'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['modbus-502']],
        's7comm'      => ['label' => 'Siemens S7 PLC',    'families' => ['ot'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['s7comm-102']],
        'bacnet'      => ['label' => 'BACnet/IP controller', 'families' => ['ot'], 'process_units' => 1, 'probe_id' => 'udp-echo-v1', 'udp_class' => 'strict-datagram-v1', 'endpoint_ids' => ['bacnet-47808-udp']],
        'ethernet-ip' => ['label' => 'EtherNet/IP',       'families' => ['ot'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['ethernet-ip-44818']],
        'dnp3'        => ['label' => 'DNP3 outstation',   'families' => ['ot'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['dnp3-20000']],
        'coap'        => ['label' => 'CoAP',              'families' => ['ot', 'neutral'], 'process_units' => 1, 'probe_id' => 'udp-echo-v1', 'udp_class' => 'strict-datagram-v1', 'endpoint_ids' => ['coap-5683-udp']],
        'snmp'        => ['label' => 'SNMP agent',        'families' => ['ot', 'windows', 'linux', 'neutral'], 'process_units' => 1, 'probe_id' => 'udp-echo-v1', 'udp_class' => 'strict-datagram-v1', 'endpoint_ids' => ['snmp-161-udp']],
        'ipmi'        => ['label' => 'IPMI/BMC',          'families' => ['ot', 'windows', 'neutral'], 'process_units' => 1, 'probe_id' => 'udp-echo-v1', 'udp_class' => 'strict-datagram-v1', 'endpoint_ids' => ['ipmi-623-udp']],
        'ntp'         => ['label' => 'NTP',               'families' => ['neutral', 'linux'], 'process_units' => 1, 'probe_id' => 'udp-echo-v1', 'udp_class' => 'strict-datagram-v1', 'endpoint_ids' => ['ntp-123-udp']],

        // --- curated nginx web-alias surfaces (no child process; canonical web serves them) ---------
        // The Docker Engine API alias must declare the docker capability so a port cannot claim Docker
        // while serving generic web bytes. Its two ports are genuinely-intentional alternatives, so
        // they form a conflict group and each requires an SSH companion (a Docker host also runs SSH).
        'docker-api-2375' => ['label' => 'Docker Engine API (plain)',  'families' => ['devops'], 'process_units' => 0, 'probe_id' => 'nginx-alias-v1', 'capability' => 'docker', 'requires' => ['ssh'], 'excludes' => ['docker-api-4243'], 'endpoint_ids' => ['http-2375']],
        'docker-api-4243' => ['label' => 'Docker Engine API (legacy)', 'families' => ['devops'], 'process_units' => 0, 'probe_id' => 'nginx-alias-v1', 'capability' => 'docker', 'requires' => ['ssh'], 'excludes' => ['docker-api-2375'], 'endpoint_ids' => ['http-4243']],
        'web-alt-http'    => ['label' => 'alt-HTTP (8080)',            'families' => ['linux', 'devops', 'windows', 'neutral'], 'process_units' => 0, 'probe_id' => 'nginx-alias-v1', 'endpoint_ids' => ['http-8080']],
    ],

    // Genuinely-intentional alternatives: `all` mode must pick exactly one member per group; a bind or
    // external-tuple collision that is NOT in a declared conflict group is a catalog error, never a
    // silent resolver choice.
    'conflict_groups' => [
        'docker-api' => ['docker-api-2375', 'docker-api-4243'],
    ],

    // Conservative named bundles (spec §4). Required members always present; optional slots pick at
    // most one member by stable deploy-seed ranking. Only `bootstrap: true` bundles are eligible for
    // first-boot auto-selection; `all` is never chosen automatically.
    'bundles' => [
        'web-only' => [
            'label' => 'Web only', 'base_family' => 'neutral', 'bootstrap' => false,
            'required' => [], 'optional_slots' => [],
        ],
        'linux-web' => [
            'label' => 'Linux web server', 'base_family' => 'linux', 'bootstrap' => true,
            'required' => ['ssh'],
            'optional_slots' => [
                'datastore' => ['mysql', 'postgresql', 'redis', 'mongodb'],
                'http-alias' => ['web-alt-http'],
            ],
        ],
        'windows-business' => [
            'label' => 'Windows business server', 'base_family' => 'windows', 'bootstrap' => true,
            'required' => ['smb', 'rdp'],
            'optional_slots' => [
                'mgmt' => ['mssql', 'winrm'],
            ],
        ],
        'voip-pbx' => [
            'label' => 'VoIP / PBX', 'base_family' => 'voip', 'bootstrap' => true,
            'required' => ['sip'],
            'optional_slots' => [
                'nat' => ['stun'],
            ],
        ],
        'ot-modbus-plc' => [
            'label' => 'OT: Modbus PLC', 'base_family' => 'ot', 'bootstrap' => true,
            'required' => ['modbus'], 'optional_slots' => ['mon' => ['snmp']],
        ],
        'ot-siemens-plc' => [
            'label' => 'OT: Siemens S7 PLC', 'base_family' => 'ot', 'bootstrap' => true,
            'required' => ['s7comm'], 'optional_slots' => ['mon' => ['snmp']],
        ],
        'ot-building-controller' => [
            'label' => 'OT: building controller', 'base_family' => 'ot', 'bootstrap' => true,
            'required' => ['bacnet'], 'optional_slots' => ['mon' => ['snmp']],
        ],
        'ot-ethernet-ip' => [
            'label' => 'OT: EtherNet/IP', 'base_family' => 'ot', 'bootstrap' => true,
            'required' => ['ethernet-ip'], 'optional_slots' => ['mon' => ['snmp']],
        ],
        'devops-container' => [
            'label' => 'DevOps container host', 'base_family' => 'devops', 'bootstrap' => false,
            'required' => ['ssh', 'docker-api-2375'],
            'optional_slots' => ['datastore' => ['redis', 'postgresql', 'mongodb']],
        ],
    ],
];
