<?php

declare(strict_types=1);

/**
 * FP-0808 infra-wiki tool-archetype catalog. Static product facts the {@see \Funnypot\App\Tarpit\InfraWiki}
 * generator instantiates per deploy (seeded host/version/owner/status/edges) into a sprawling fake
 * infrastructure inventory. Each row is a generic real-tool archetype across the 13 lifecycle categories
 * (spec §"Content taxonomy"): name, category, typical port(s), a version pool spanning ancient→current,
 * OS/stack affinity, a status-weight bias, and an edge-role hint.
 *
 * INVARIANTS (enforced by the fingerprint test over the rendered corpus):
 *  - Only generic product names and real version strings — never a CVE id, nuclei matcher word, CRS rule
 *    id / `msg`, or ModSecurity/OWASP_CRS marker. A real version number is not a detector signature; the
 *    per-deploy host/owner/status/edge variation is the anti-fingerprint property (same posture as
 *    PersonaIdentity::PRODUCT_VERSION_POOLS).
 *  - Version strings carry dots, so no field here can form a bare 6-digit run; the generator routes every
 *    GENERATED token (hosts, slugs, derivation constants) through InertSecret, and the test scans the full
 *    rendered prose across many seeds.
 *
 * statusWeight biases which lifecycle status a service lands in per deploy, so ~40% of the fleet carries
 * tech-debt/duplication (legacy/deprecated/migrating/archived) — the spider-web the spec wants.
 */

// Status-weight presets (referenced below to keep the rows terse). Keys are the lifecycle statuses the
// generator picks from; higher weight ⇒ more likely. The archetype's role in the stack sets the bias.
$current    = ['prod' => 6, 'staging' => 2, 'migrating' => 1];
$coreProd   = ['prod' => 8, 'staging' => 1];
$migrating  = ['migrating' => 5, 'staging' => 3, 'prod' => 2];
$legacy     = ['legacy' => 5, 'deprecated' => 3, 'prod' => 1, 'archived' => 1];
$deprecated = ['deprecated' => 5, 'archived' => 3, 'legacy' => 2];
$archived   = ['archived' => 6, 'legacy' => 2];
$oneTeam    = ['prod' => 3, 'staging' => 3, 'legacy' => 2];

return [
    // 1. Source control.
    ['name' => 'GitLab', 'category' => 'scm', 'ports' => [443, 22, 80], 'versions' => ['16.7.2', '16.3.6', '15.11.13', '15.6.1'], 'stack' => ['linux', 'ruby'], 'statusWeight' => $coreProd, 'role' => 'scm'],
    ['name' => 'GitHub Enterprise', 'category' => 'scm', 'ports' => [443, 22], 'versions' => ['3.11.4', '3.10.6', '3.9.11'], 'stack' => ['linux'], 'statusWeight' => $migrating, 'role' => 'scm'],
    ['name' => 'Gerrit', 'category' => 'scm', 'ports' => [8080, 29418], 'versions' => ['3.8.1', '3.6.4', '3.4.5'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $deprecated, 'role' => 'scm'],
    ['name' => 'Bitbucket', 'category' => 'scm', 'ports' => [7990, 7999], 'versions' => ['8.9.4', '7.21.16', '7.6.0'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'scm'],
    ['name' => 'Subversion', 'category' => 'scm', 'ports' => [3690, 443], 'versions' => ['1.14.2', '1.10.6', '1.8.19'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'scm'],
    ['name' => 'Mercurial', 'category' => 'scm', 'ports' => [8000, 443], 'versions' => ['6.4.5', '5.9.3', '4.5.3'], 'stack' => ['python', 'linux'], 'statusWeight' => $archived, 'role' => 'scm'],
    ['name' => 'CVS', 'category' => 'scm', 'ports' => [2401], 'versions' => ['1.12.13', '1.11.23'], 'stack' => ['linux'], 'statusWeight' => $archived, 'role' => 'scm'],

    // 2. CI/CD.
    ['name' => 'Jenkins', 'category' => 'cicd', 'ports' => [8080, 50000], 'versions' => ['2.426.1', '2.414.3', '2.401.3', '2.361.4'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $legacy, 'role' => 'deployer'],
    ['name' => 'GitLab CI', 'category' => 'cicd', 'ports' => [443, 8093], 'versions' => ['16.7.2', '16.3.6', '15.11.13'], 'stack' => ['linux', 'go'], 'statusWeight' => $current, 'role' => 'deployer'],
    ['name' => 'TeamCity', 'category' => 'cicd', 'ports' => [8111], 'versions' => ['2023.11.1', '2023.05.4', '2022.10.3'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'deployer'],
    ['name' => 'Bamboo', 'category' => 'cicd', 'ports' => [8085, 54663], 'versions' => ['9.4.2', '8.2.7', '7.2.6'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $deprecated, 'role' => 'deployer'],
    ['name' => 'Argo CD', 'category' => 'cicd', 'ports' => [443, 8083], 'versions' => ['2.9.3', '2.7.14', '2.6.15'], 'stack' => ['go', 'kubernetes'], 'statusWeight' => $current, 'role' => 'deployer'],
    ['name' => 'Spinnaker', 'category' => 'cicd', 'ports' => [8084, 9000], 'versions' => ['1.32.1', '1.30.3', '1.28.1'], 'stack' => ['jvm', 'kubernetes'], 'statusWeight' => $oneTeam, 'role' => 'deployer'],
    ['name' => 'Drone', 'category' => 'cicd', 'ports' => [80, 443], 'versions' => ['2.21.0', '2.16.0', '1.10.1'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'deployer'],
    ['name' => 'CircleCI Server', 'category' => 'cicd', 'ports' => [443, 8800], 'versions' => ['4.3.0', '3.4.2'], 'stack' => ['kubernetes'], 'statusWeight' => $oneTeam, 'role' => 'deployer'],
    ['name' => 'Octopus Deploy', 'category' => 'cicd', 'ports' => [443, 10933], 'versions' => ['2023.4.8', '2022.4.10', '2021.3.12'], 'stack' => ['dotnet', 'windows'], 'statusWeight' => $oneTeam, 'role' => 'deployer'],

    // 3. Artifacts / registry.
    ['name' => 'Nexus Repository', 'category' => 'artifacts', 'ports' => [8081, 8443], 'versions' => ['3.63.0', '3.58.1', '3.45.0'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'store'],
    ['name' => 'Artifactory', 'category' => 'artifacts', 'ports' => [8081, 8082], 'versions' => ['7.71.5', '7.63.14', '7.49.10'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'store'],
    ['name' => 'Harbor', 'category' => 'artifacts', 'ports' => [443, 80], 'versions' => ['2.9.1', '2.7.4', '2.5.6'], 'stack' => ['go', 'kubernetes'], 'statusWeight' => $current, 'role' => 'store'],
    ['name' => 'Docker Registry', 'category' => 'artifacts', 'ports' => [5000, 443], 'versions' => ['2.8.3', '2.8.1', '2.7.1'], 'stack' => ['go', 'linux'], 'statusWeight' => $legacy, 'role' => 'store'],
    ['name' => 'Verdaccio', 'category' => 'artifacts', 'ports' => [4873], 'versions' => ['5.27.0', '5.15.0', '4.13.2'], 'stack' => ['node', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'store'],
    ['name' => 'devpi', 'category' => 'artifacts', 'ports' => [3141], 'versions' => ['6.9.2', '6.4.0', '5.5.1'], 'stack' => ['python', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'store'],
    ['name' => 'Chocolatey Server', 'category' => 'artifacts', 'ports' => [443], 'versions' => ['1.4.0', '0.12.4', '0.10.15'], 'stack' => ['dotnet', 'windows'], 'statusWeight' => $oneTeam, 'role' => 'store'],

    // 4. Containers / orchestration.
    ['name' => 'Amazon EKS', 'category' => 'orchestration', 'ports' => [443, 10250], 'versions' => ['1.28', '1.27', '1.25'], 'stack' => ['kubernetes'], 'statusWeight' => $coreProd, 'role' => 'platform'],
    ['name' => 'Google GKE', 'category' => 'orchestration', 'ports' => [443, 10250], 'versions' => ['1.28', '1.26', '1.24'], 'stack' => ['kubernetes'], 'statusWeight' => $current, 'role' => 'platform'],
    ['name' => 'Rancher RKE', 'category' => 'orchestration', 'ports' => [443, 6443], 'versions' => ['1.25.11', '1.24.15', '1.22.17'], 'stack' => ['kubernetes', 'linux'], 'statusWeight' => $legacy, 'role' => 'platform'],
    ['name' => 'Docker Swarm', 'category' => 'orchestration', 'ports' => [2377, 7946], 'versions' => ['24.0.7', '23.0.6', '20.10.24'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'platform'],
    ['name' => 'HashiCorp Nomad', 'category' => 'orchestration', 'ports' => [4646, 4647, 4648], 'versions' => ['1.6.3', '1.5.8', '1.3.15'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'platform'],
    ['name' => 'OpenShift', 'category' => 'orchestration', 'ports' => [443, 8443], 'versions' => ['4.13', '4.11', '4.9'], 'stack' => ['kubernetes'], 'statusWeight' => $migrating, 'role' => 'platform'],
    ['name' => 'Apache Mesos', 'category' => 'orchestration', 'ports' => [5050, 5051], 'versions' => ['1.11.0', '1.9.0', '1.7.2'], 'stack' => ['linux'], 'statusWeight' => $archived, 'role' => 'platform'],

    // 5. Config / secrets / IaC.
    ['name' => 'HashiCorp Vault', 'category' => 'config', 'ports' => [8200, 8201], 'versions' => ['1.15.2', '1.14.4', '1.12.7'], 'stack' => ['go', 'linux'], 'statusWeight' => $coreProd, 'role' => 'secrets'],
    ['name' => 'Consul', 'category' => 'config', 'ports' => [8500, 8300, 8301], 'versions' => ['1.17.0', '1.15.6', '1.13.9'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'secrets'],
    ['name' => 'etcd', 'category' => 'config', 'ports' => [2379, 2380], 'versions' => ['3.5.10', '3.5.7', '3.4.27'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'secrets'],
    ['name' => 'Terraform Enterprise', 'category' => 'config', 'ports' => [443, 8800], 'versions' => ['1.6.4', '1.5.7', '1.3.10'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'iac'],
    ['name' => 'AWS CloudFormation', 'category' => 'config', 'ports' => [443], 'versions' => ['2023.11', '2023.04'], 'stack' => ['aws'], 'statusWeight' => $legacy, 'role' => 'iac'],
    ['name' => 'Pulumi', 'category' => 'config', 'ports' => [443], 'versions' => ['3.95.0', '3.82.1', '3.68.0'], 'stack' => ['node', 'go'], 'statusWeight' => $oneTeam, 'role' => 'iac'],
    ['name' => 'Ansible AWX', 'category' => 'config', 'ports' => [443, 80], 'versions' => ['23.3.1', '21.14.0', '19.5.1'], 'stack' => ['python', 'kubernetes'], 'statusWeight' => $current, 'role' => 'iac'],
    ['name' => 'Puppet', 'category' => 'config', 'ports' => [8140, 8081], 'versions' => ['8.3.1', '7.27.0', '6.28.0'], 'stack' => ['ruby', 'linux'], 'statusWeight' => $legacy, 'role' => 'iac'],
    ['name' => 'Chef Infra Server', 'category' => 'config', 'ports' => [443, 80], 'versions' => ['15.7.0', '14.13.11', '12.19.31'], 'stack' => ['ruby', 'linux'], 'statusWeight' => $deprecated, 'role' => 'iac'],
    ['name' => 'SaltStack', 'category' => 'config', 'ports' => [4505, 4506], 'versions' => ['3006.4', '3005.2', '3004.2'], 'stack' => ['python', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'iac'],

    // 6. Databases.
    ['name' => 'PostgreSQL', 'category' => 'database', 'ports' => [5432], 'versions' => ['16.1', '15.5', '14.10', '13.13'], 'stack' => ['linux'], 'statusWeight' => $coreProd, 'role' => 'datastore'],
    ['name' => 'MySQL', 'category' => 'database', 'ports' => [3306], 'versions' => ['8.0.35', '5.7.44', '5.6.51'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'datastore'],
    ['name' => 'Oracle Database', 'category' => 'database', 'ports' => [1521, 1522], 'versions' => ['19.21', '19.3', '12.2.0.1'], 'stack' => ['linux'], 'statusWeight' => $migrating, 'role' => 'datastore'],
    ['name' => 'MongoDB', 'category' => 'database', 'ports' => [27017, 27018], 'versions' => ['7.0.4', '6.0.12', '5.0.23'], 'stack' => ['linux'], 'statusWeight' => $current, 'role' => 'datastore'],
    ['name' => 'Cassandra', 'category' => 'database', 'ports' => [9042, 7000], 'versions' => ['4.1.3', '4.0.11', '3.11.16'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],
    ['name' => 'Redis', 'category' => 'database', 'ports' => [6379, 26379], 'versions' => ['7.2.3', '7.0.14', '6.2.14'], 'stack' => ['linux'], 'statusWeight' => $current, 'role' => 'cache'],
    ['name' => 'Memcached', 'category' => 'database', 'ports' => [11211], 'versions' => ['1.6.22', '1.6.18', '1.5.22'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'cache'],
    ['name' => 'Elasticsearch', 'category' => 'database', 'ports' => [9200, 9300], 'versions' => ['8.11.1', '7.17.15', '6.8.23'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'datastore'],
    ['name' => 'ClickHouse', 'category' => 'database', 'ports' => [8123, 9004], 'versions' => ['23.10.3', '23.3.18', '22.8.21'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],
    ['name' => 'Neo4j', 'category' => 'database', 'ports' => [7474, 7687], 'versions' => ['5.14.0', '5.9.0', '4.4.28'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],
    ['name' => 'CouchDB', 'category' => 'database', 'ports' => [5984, 6984], 'versions' => ['3.3.3', '3.2.2', '2.3.1'], 'stack' => ['erlang', 'linux'], 'statusWeight' => $archived, 'role' => 'datastore'],
    ['name' => 'Microsoft SQL Server', 'category' => 'database', 'ports' => [1433, 1434], 'versions' => ['2022-CU10', '2019-CU25', '2017-CU31'], 'stack' => ['windows'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],

    // 7. Messaging / streaming.
    ['name' => 'Apache Kafka', 'category' => 'messaging', 'ports' => [9092, 9093], 'versions' => ['3.6.0', '3.4.1', '2.8.2'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $coreProd, 'role' => 'bus'],
    ['name' => 'RabbitMQ', 'category' => 'messaging', 'ports' => [5672, 15672], 'versions' => ['3.12.10', '3.11.28', '3.9.29'], 'stack' => ['erlang', 'linux'], 'statusWeight' => $current, 'role' => 'bus'],
    ['name' => 'NATS', 'category' => 'messaging', 'ports' => [4222, 8222], 'versions' => ['2.10.7', '2.9.23', '2.8.4'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'bus'],
    ['name' => 'ActiveMQ', 'category' => 'messaging', 'ports' => [61616, 8161], 'versions' => ['5.18.3', '5.17.6', '5.15.16'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $legacy, 'role' => 'bus'],
    ['name' => 'Apache Pulsar', 'category' => 'messaging', 'ports' => [6650, 8080], 'versions' => ['3.1.1', '2.11.3', '2.10.5'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'bus'],

    // 8. Observability.
    ['name' => 'Prometheus', 'category' => 'observability', 'ports' => [9090, 9091], 'versions' => ['2.48.0', '2.45.2', '2.37.9'], 'stack' => ['go', 'linux'], 'statusWeight' => $coreProd, 'role' => 'monitor'],
    ['name' => 'Grafana', 'category' => 'observability', 'ports' => [3000], 'versions' => ['10.2.2', '9.5.15', '8.5.27'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'monitor'],
    ['name' => 'Splunk', 'category' => 'observability', 'ports' => [8000, 8089, 9997], 'versions' => ['9.1.2', '9.0.7', '8.2.12'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'monitor'],
    ['name' => 'Kibana', 'category' => 'observability', 'ports' => [5601], 'versions' => ['8.11.1', '7.17.15', '6.8.23'], 'stack' => ['node', 'linux'], 'statusWeight' => $current, 'role' => 'monitor'],
    ['name' => 'Sentry', 'category' => 'observability', 'ports' => [9000, 443], 'versions' => ['23.11.0', '23.6.2', '22.12.0'], 'stack' => ['python', 'linux'], 'statusWeight' => $current, 'role' => 'monitor'],
    ['name' => 'Jaeger', 'category' => 'observability', 'ports' => [16686, 14268], 'versions' => ['1.51.0', '1.47.0', '1.41.0'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'monitor'],
    ['name' => 'Zipkin', 'category' => 'observability', 'ports' => [9411], 'versions' => ['2.24.3', '2.23.19', '2.21.7'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $deprecated, 'role' => 'monitor'],
    ['name' => 'Nagios Core', 'category' => 'observability', 'ports' => [80, 443], 'versions' => ['4.5.0', '4.4.14', '4.3.4'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'monitor'],
    ['name' => 'Zabbix', 'category' => 'observability', 'ports' => [10051, 10050, 80], 'versions' => ['6.4.9', '6.0.24', '5.0.42'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'monitor'],

    // 9. Marketing / analytics / data.
    ['name' => 'Matomo', 'category' => 'analytics', 'ports' => [443, 80], 'versions' => ['4.16.0', '4.12.3', '3.14.1'], 'stack' => ['php', 'linux'], 'statusWeight' => $current, 'role' => 'analytics'],
    ['name' => 'Metabase', 'category' => 'analytics', 'ports' => [3000], 'versions' => ['0.47.8', '0.46.6', '0.44.6'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'analytics'],
    ['name' => 'Apache Superset', 'category' => 'analytics', 'ports' => [8088], 'versions' => ['3.0.1', '2.1.1', '1.5.3'], 'stack' => ['python', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'analytics'],
    ['name' => 'Apache Airflow', 'category' => 'analytics', 'ports' => [8080], 'versions' => ['2.7.3', '2.6.3', '2.5.3'], 'stack' => ['python', 'linux'], 'statusWeight' => $current, 'role' => 'analytics'],
    ['name' => 'dbt', 'category' => 'analytics', 'ports' => [8580], 'versions' => ['1.7.3', '1.6.9', '1.5.9'], 'stack' => ['python', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'analytics'],
    ['name' => 'Looker', 'category' => 'analytics', 'ports' => [443, 9999], 'versions' => ['23.20', '23.12', '23.6'], 'stack' => ['jvm'], 'statusWeight' => $oneTeam, 'role' => 'analytics'],
    ['name' => 'Snowflake Connector', 'category' => 'analytics', 'ports' => [443], 'versions' => ['7.3.2', '7.0.1', '6.25.0'], 'stack' => ['python'], 'statusWeight' => $current, 'role' => 'analytics'],
    ['name' => 'Fivetran Agent', 'category' => 'analytics', 'ports' => [443], 'versions' => ['2.1.0', '1.9.0'], 'stack' => ['jvm'], 'statusWeight' => $oneTeam, 'role' => 'analytics'],
    ['name' => 'Databricks', 'category' => 'analytics', 'ports' => [443, 8443], 'versions' => ['13.3-LTS', '12.2-LTS', '11.3-LTS'], 'stack' => ['jvm', 'spark'], 'statusWeight' => $oneTeam, 'role' => 'analytics'],

    // 10. Collaboration / dev tooling.
    ['name' => 'Jira', 'category' => 'collaboration', 'ports' => [8080, 443], 'versions' => ['9.12.0', '9.4.14', '8.20.30'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'app'],
    ['name' => 'Confluence', 'category' => 'collaboration', 'ports' => [8090, 443], 'versions' => ['8.5.4', '7.19.17', '7.13.20'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'app'],
    ['name' => 'Mattermost', 'category' => 'collaboration', 'ports' => [8065, 443], 'versions' => ['9.2.3', '8.1.7', '7.8.11'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'app'],
    ['name' => 'Rocket.Chat', 'category' => 'collaboration', 'ports' => [3000, 443], 'versions' => ['6.5.0', '6.3.6', '5.4.9'], 'stack' => ['node', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'app'],
    ['name' => 'Outline', 'category' => 'collaboration', 'ports' => [3000], 'versions' => ['0.74.0', '0.70.2', '0.67.0'], 'stack' => ['node', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'app'],
    ['name' => 'SharePoint', 'category' => 'collaboration', 'ports' => [443, 80], 'versions' => ['2019-CU', '2016-CU', '2013-SP1'], 'stack' => ['dotnet', 'windows'], 'statusWeight' => $legacy, 'role' => 'app'],
    ['name' => 'Redmine', 'category' => 'collaboration', 'ports' => [3000, 80], 'versions' => ['5.1.1', '5.0.6', '4.2.11'], 'stack' => ['ruby', 'linux'], 'statusWeight' => $archived, 'role' => 'app'],

    // 11. Backup / storage / legacy mess.
    ['name' => 'WebDAV Backup', 'category' => 'backup', 'ports' => [443, 80], 'versions' => ['2.4.58', '2.4.54', '2.4.41'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'backup'],
    ['name' => 'NFS Server', 'category' => 'backup', 'ports' => [2049, 111], 'versions' => ['2.6.3', '2.5.4', '1.3.4'], 'stack' => ['linux'], 'statusWeight' => $current, 'role' => 'backup'],
    ['name' => 'MinIO', 'category' => 'backup', 'ports' => [9000, 9001], 'versions' => ['2023-11-20', '2023-07-07', '2022-10-29'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'store'],
    ['name' => 'Bacula', 'category' => 'backup', 'ports' => [9101, 9102, 9103], 'versions' => ['13.0.3', '11.0.6', '9.6.7'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'backup'],
    ['name' => 'Veeam Backup', 'category' => 'backup', 'ports' => [9392, 9393, 10001], 'versions' => ['12.1', '11a', '10.0'], 'stack' => ['windows'], 'statusWeight' => $oneTeam, 'role' => 'backup'],
    ['name' => 'ProFTPD', 'category' => 'backup', 'ports' => [21, 990], 'versions' => ['1.3.8a', '1.3.7c', '1.3.6'], 'stack' => ['linux'], 'statusWeight' => $deprecated, 'role' => 'backup'],
    ['name' => 'Samba', 'category' => 'backup', 'ports' => [445, 139], 'versions' => ['4.19.3', '4.17.12', '4.13.17'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'store'],
    ['name' => 'rsync Daemon', 'category' => 'backup', 'ports' => [873], 'versions' => ['3.2.7', '3.1.3', '3.1.2'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'backup'],

    // 12. Auth / identity.
    ['name' => 'Keycloak', 'category' => 'auth', 'ports' => [8080, 8443], 'versions' => ['23.0.1', '22.0.5', '21.1.2'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'idp'],
    ['name' => 'OpenLDAP', 'category' => 'auth', 'ports' => [389, 636], 'versions' => ['2.6.6', '2.5.17', '2.4.59'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'idp'],
    ['name' => 'FreeIPA', 'category' => 'auth', 'ports' => [443, 389, 88], 'versions' => ['4.11.0', '4.10.2', '4.9.13'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'idp'],
    ['name' => 'FreeRADIUS', 'category' => 'auth', 'ports' => [1812, 1813], 'versions' => ['3.2.3', '3.0.26', '3.0.21'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'idp'],
    ['name' => 'MIT Kerberos KDC', 'category' => 'auth', 'ports' => [88, 464, 749], 'versions' => ['1.21.2', '1.19.4', '1.17'], 'stack' => ['linux'], 'statusWeight' => $deprecated, 'role' => 'idp'],
    ['name' => 'Authelia', 'category' => 'auth', 'ports' => [9091, 443], 'versions' => ['4.37.5', '4.36.9', '4.35.6'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'idp'],

    // 13. Networking / edge.
    ['name' => 'nginx', 'category' => 'edge', 'ports' => [80, 443], 'versions' => ['1.25.3', '1.24.0', '1.22.1'], 'stack' => ['linux'], 'statusWeight' => $coreProd, 'role' => 'edge'],
    ['name' => 'HAProxy', 'category' => 'edge', 'ports' => [80, 443, 8404], 'versions' => ['2.8.5', '2.6.16', '2.4.24'], 'stack' => ['linux'], 'statusWeight' => $current, 'role' => 'edge'],
    ['name' => 'Envoy', 'category' => 'edge', 'ports' => [9901, 10000], 'versions' => ['1.28.0', '1.26.4', '1.24.10'], 'stack' => ['linux', 'kubernetes'], 'statusWeight' => $current, 'role' => 'edge'],
    ['name' => 'Istio', 'category' => 'edge', 'ports' => [15021, 15010, 15012], 'versions' => ['1.20.0', '1.18.5', '1.16.7'], 'stack' => ['kubernetes'], 'statusWeight' => $current, 'role' => 'edge'],
    ['name' => 'Traefik', 'category' => 'edge', 'ports' => [80, 443, 8080], 'versions' => ['2.10.7', '2.9.10', '2.6.7'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'edge'],
    ['name' => 'Apache HTTP Server', 'category' => 'edge', 'ports' => [80, 443], 'versions' => ['2.4.58', '2.4.54', '2.4.41'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'edge'],
    ['name' => 'Squid', 'category' => 'edge', 'ports' => [3128, 8080], 'versions' => ['6.5', '5.9', '4.17'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'edge'],
    ['name' => 'OpenVPN', 'category' => 'edge', 'ports' => [1194, 443], 'versions' => ['2.6.8', '2.5.9', '2.4.12'], 'stack' => ['linux'], 'statusWeight' => $current, 'role' => 'edge'],
    ['name' => 'WireGuard', 'category' => 'edge', 'ports' => [51820], 'versions' => ['1.0.20220627', '1.0.20210914'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'edge'],
    ['name' => 'pfSense', 'category' => 'edge', 'ports' => [443, 80], 'versions' => ['2.7.1', '2.6.0', '2.5.2'], 'stack' => ['bsd'], 'statusWeight' => $oneTeam, 'role' => 'edge'],
    ['name' => 'Kong Gateway', 'category' => 'edge', 'ports' => [8000, 8001, 8443], 'versions' => ['3.5.0', '3.3.1', '2.8.3'], 'stack' => ['linux'], 'statusWeight' => $current, 'role' => 'edge'],
    ['name' => 'Caddy', 'category' => 'edge', 'ports' => [80, 443, 2019], 'versions' => ['2.7.6', '2.6.4', '2.5.2'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'edge'],
    ['name' => 'Varnish Cache', 'category' => 'edge', 'ports' => [80, 6081, 6082], 'versions' => ['7.4.2', '7.1.1', '6.0.11'], 'stack' => ['linux'], 'statusWeight' => $legacy, 'role' => 'edge'],

    // Additional source control.
    ['name' => 'Gitea', 'category' => 'scm', 'ports' => [3000, 22], 'versions' => ['1.21.1', '1.20.5', '1.18.5'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'scm'],
    ['name' => 'Phabricator', 'category' => 'scm', 'ports' => [443, 80], 'versions' => ['2020.52', '2019.42'], 'stack' => ['php', 'linux'], 'statusWeight' => $archived, 'role' => 'scm'],

    // Additional CI/CD.
    ['name' => 'Concourse CI', 'category' => 'cicd', 'ports' => [8080, 2222], 'versions' => ['7.11.0', '7.9.1', '7.6.0'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'deployer'],
    ['name' => 'GoCD', 'category' => 'cicd', 'ports' => [8153, 8154], 'versions' => ['23.4.0', '23.1.0', '22.3.0'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $deprecated, 'role' => 'deployer'],
    ['name' => 'Woodpecker CI', 'category' => 'cicd', 'ports' => [8000, 9000], 'versions' => ['2.0.0', '1.0.5', '0.15.11'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'deployer'],
    ['name' => 'Flux CD', 'category' => 'cicd', 'ports' => [9292, 3030], 'versions' => ['2.2.0', '2.1.2', '0.41.2'], 'stack' => ['go', 'kubernetes'], 'statusWeight' => $current, 'role' => 'deployer'],

    // Additional artifacts.
    ['name' => 'Sonatype IQ Server', 'category' => 'artifacts', 'ports' => [8070, 8071], 'versions' => ['163', '157', '149'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'store'],
    ['name' => 'Cloudsmith Proxy', 'category' => 'artifacts', 'ports' => [443], 'versions' => ['1.4.0', '1.2.1'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'store'],

    // Additional orchestration.
    ['name' => 'k3s', 'category' => 'orchestration', 'ports' => [6443, 10250], 'versions' => ['1.28.3', '1.26.9', '1.24.17'], 'stack' => ['kubernetes', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'platform'],
    ['name' => 'MicroK8s', 'category' => 'orchestration', 'ports' => [16443, 10250], 'versions' => ['1.28', '1.26', '1.24'], 'stack' => ['kubernetes', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'platform'],

    // Additional config / secrets / IaC.
    ['name' => 'Spacelift Worker', 'category' => 'config', 'ports' => [443], 'versions' => ['1.4.0', '1.2.0'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'iac'],
    ['name' => 'OpenBao', 'category' => 'config', 'ports' => [8200, 8201], 'versions' => ['2.0.0', '1.15.0'], 'stack' => ['go', 'linux'], 'statusWeight' => $migrating, 'role' => 'secrets'],

    // Additional databases.
    ['name' => 'MariaDB', 'category' => 'database', 'ports' => [3306], 'versions' => ['11.2.2', '10.11.6', '10.6.16'], 'stack' => ['linux'], 'statusWeight' => $current, 'role' => 'datastore'],
    ['name' => 'InfluxDB', 'category' => 'database', 'ports' => [8086, 8088], 'versions' => ['2.7.4', '2.6.1', '1.8.10'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],
    ['name' => 'TimescaleDB', 'category' => 'database', 'ports' => [5432], 'versions' => ['2.13.0', '2.11.2', '2.8.1'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],
    ['name' => 'CockroachDB', 'category' => 'database', 'ports' => [26257, 8080], 'versions' => ['23.1.13', '22.2.17', '21.2.17'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],
    ['name' => 'ScyllaDB', 'category' => 'database', 'ports' => [9042, 9160], 'versions' => ['5.4.0', '5.2.9', '5.0.13'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'datastore'],

    // Additional messaging.
    ['name' => 'Kafka Connect', 'category' => 'messaging', 'ports' => [8083], 'versions' => ['3.6.0', '3.4.1', '2.8.2'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'bus'],
    ['name' => 'Schema Registry', 'category' => 'messaging', 'ports' => [8081], 'versions' => ['7.5.2', '7.3.4', '6.2.12'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $current, 'role' => 'bus'],
    ['name' => 'Mosquitto', 'category' => 'messaging', 'ports' => [1883, 8883], 'versions' => ['2.0.18', '2.0.15', '1.6.15'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'bus'],
    ['name' => 'Redpanda', 'category' => 'messaging', 'ports' => [9092, 9644], 'versions' => ['23.3.1', '23.1.13', '22.3.17'], 'stack' => ['linux'], 'statusWeight' => $oneTeam, 'role' => 'bus'],

    // Additional observability.
    ['name' => 'Loki', 'category' => 'observability', 'ports' => [3100], 'versions' => ['2.9.3', '2.8.6', '2.6.1'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'monitor'],
    ['name' => 'Tempo', 'category' => 'observability', 'ports' => [3200, 4317], 'versions' => ['2.3.1', '2.1.1', '1.5.0'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'monitor'],
    ['name' => 'Thanos', 'category' => 'observability', 'ports' => [10901, 10902], 'versions' => ['0.32.5', '0.30.2', '0.28.1'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'monitor'],
    ['name' => 'VictoriaMetrics', 'category' => 'observability', 'ports' => [8428, 8089], 'versions' => ['1.95.1', '1.91.3', '1.87.5'], 'stack' => ['go', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'monitor'],
    ['name' => 'Alertmanager', 'category' => 'observability', 'ports' => [9093, 9094], 'versions' => ['0.26.0', '0.25.0', '0.24.0'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'monitor'],
    ['name' => 'Fluentd', 'category' => 'observability', 'ports' => [24224, 24220], 'versions' => ['1.16.3', '1.15.3', '1.14.6'], 'stack' => ['ruby', 'linux'], 'statusWeight' => $current, 'role' => 'monitor'],
    ['name' => 'Graphite', 'category' => 'observability', 'ports' => [2003, 8080], 'versions' => ['1.1.10', '1.1.8', '1.0.2'], 'stack' => ['python', 'linux'], 'statusWeight' => $legacy, 'role' => 'monitor'],
    ['name' => 'Uptime Kuma', 'category' => 'observability', 'ports' => [3001], 'versions' => ['1.23.11', '1.21.3', '1.19.6'], 'stack' => ['node', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'monitor'],

    // Additional analytics.
    ['name' => 'Redash', 'category' => 'analytics', 'ports' => [5000, 443], 'versions' => ['10.1.0', '8.0.2'], 'stack' => ['python', 'linux'], 'statusWeight' => $deprecated, 'role' => 'analytics'],
    ['name' => 'Apache NiFi', 'category' => 'analytics', 'ports' => [8443, 8080], 'versions' => ['1.24.0', '1.21.0', '1.16.3'], 'stack' => ['jvm', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'analytics'],

    // Additional collaboration.
    ['name' => 'Wiki.js', 'category' => 'collaboration', 'ports' => [3000, 443], 'versions' => ['2.5.307', '2.5.291'], 'stack' => ['node', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'app'],
    ['name' => 'BookStack', 'category' => 'collaboration', 'ports' => [443, 80], 'versions' => ['23.10.2', '23.06.2', '22.11.1'], 'stack' => ['php', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'app'],
    ['name' => 'Taiga', 'category' => 'collaboration', 'ports' => [443, 80], 'versions' => ['6.7.3', '6.5.1'], 'stack' => ['python', 'linux'], 'statusWeight' => $archived, 'role' => 'app'],

    // Additional auth / identity.
    ['name' => 'Dex', 'category' => 'auth', 'ports' => [5556, 5557], 'versions' => ['2.37.0', '2.35.3', '2.32.0'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'idp'],
    ['name' => 'oauth2-proxy', 'category' => 'auth', 'ports' => [4180], 'versions' => ['7.5.1', '7.4.0', '7.2.1'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'idp'],

    // Additional backup / storage.
    ['name' => 'Restic REST Server', 'category' => 'backup', 'ports' => [8000], 'versions' => ['0.12.1', '0.11.0'], 'stack' => ['go', 'linux'], 'statusWeight' => $current, 'role' => 'backup'],
    ['name' => 'Duplicati', 'category' => 'backup', 'ports' => [8200], 'versions' => ['2.0.7.1', '2.0.6.3'], 'stack' => ['dotnet', 'linux'], 'statusWeight' => $oneTeam, 'role' => 'backup'],
];
