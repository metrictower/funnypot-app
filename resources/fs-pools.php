<?php

declare(strict_types=1);

/**
 * Factual, plausible name pools for the procedural fake filesystem. Public factual data (common Unix /
 * ecosystem names) — NEVER scanner signatures. Large on purpose: with hundreds of candidates an exact
 * string match against this repo is not proof of fakeness (the generator + this file are public).
 *
 * Shape: role => ['dirs' => string[], 'files' => string[], 'exts' => string[]].
 * The 'generic' role is merged into every other role by Pools, so per-role dir/file counts clear the
 * >=150 floor without repeating the shared base.
 */

$genericDirs = [
    // FHS + system
    'bin', 'sbin', 'lib', 'lib64', 'libexec', 'include', 'share', 'local', 'opt', 'srv', 'etc', 'var',
    'usr', 'run', 'tmp', 'boot', 'dev', 'proc', 'sys', 'mnt', 'media', 'root', 'home', 'lost+found',
    'cache', 'spool', 'lock', 'log', 'backups', 'crash', 'snap', 'mail', 'games', 'man', 'doc', 'info',
    'locale', 'zoneinfo', 'terminfo', 'fonts', 'icons', 'themes', 'pixmaps', 'applications', 'systemd',
    'cron.d', 'cron.daily', 'cron.hourly', 'cron.weekly', 'cron.monthly', 'init.d', 'rc.d', 'profile.d',
    'sysconfig', 'default', 'security', 'pam.d', 'ssl', 'certs', 'private', 'ssh', 'sudoers.d', 'apt',
    'yum.repos.d', 'dpkg', 'rpm', 'network', 'netplan', 'NetworkManager', 'resolvconf', 'udev', 'modprobe.d',
    // generic app / project
    'app', 'apps', 'www', 'html', 'public', 'public_html', 'web', 'webapps', 'sites', 'sites-available',
    'sites-enabled', 'conf', 'conf.d', 'config', 'configs', 'settings', 'data', 'db', 'database', 'store',
    'storage', 'uploads', 'downloads', 'files', 'assets', 'static', 'media', 'images', 'img', 'css', 'js',
    'vendor', 'node_modules', 'packages', 'modules', 'plugins', 'extensions', 'themes', 'templates', 'views',
    'partials', 'layouts', 'components', 'services', 'controllers', 'models', 'helpers', 'utils', 'common',
    'shared', 'core', 'internal', 'external', 'third_party', 'vendored', 'deps', 'build', 'dist', 'out',
    'target', 'bin', 'obj', 'release', 'debug', 'tmp', 'temp', 'work', 'workspace', 'projects', 'repos',
    'archive', 'archives', 'backup', 'old', 'new', 'current', 'latest', 'releases', 'snapshots', 'versions',
    'reports', 'exports', 'imports', 'inbox', 'outbox', 'queue', 'jobs', 'tasks', 'scripts', 'tools', 'bin',
    'migrations', 'seeds', 'fixtures', 'samples', 'examples', 'demo', 'sandbox', 'staging', 'prod', 'dev',
    'test', 'tests', 'spec', 'specs', 'coverage', 'docs', 'documentation', 'wiki', 'notes', 'meeting-notes',
];

$genericFiles = [
    // dotfiles / shell
    '.bashrc', '.bash_profile', '.bash_history', '.bash_logout', '.profile', '.zshrc', '.zsh_history',
    '.inputrc', '.vimrc', '.viminfo', '.nanorc', '.gitconfig', '.gitignore', '.gitignore_global',
    '.netrc', '.curlrc', '.wgetrc', '.selected_editor', '.lesshst', '.python_history', '.node_repl_history',
    '.mysql_history', '.psql_history', '.rediscli_history', '.sqlite_history', '.docker', '.dockerignore',
    // configs
    'config', 'config.json', 'config.yaml', 'config.yml', 'config.ini', 'config.php', 'config.xml',
    'config.toml', 'settings.json', 'settings.py', 'settings.ini', 'app.config', 'web.config', 'appsettings.json',
    '.env', '.env.local', '.env.example', '.env.production', 'env.sh', 'defaults.conf', 'main.conf',
    'nginx.conf', 'httpd.conf', 'apache2.conf', 'my.cnf', 'redis.conf', 'php.ini', 'crontab', 'hosts',
    'hostname', 'resolv.conf', 'fstab', 'passwd', 'group', 'shadow', 'sudoers', 'os-release', 'issue',
    'motd', 'profile', 'bashrc', 'authorized_keys', 'known_hosts', 'id_rsa', 'id_rsa.pub', 'id_ed25519',
    // logs / data
    'access.log', 'error.log', 'app.log', 'debug.log', 'system.log', 'syslog', 'auth.log', 'kern.log',
    'boot.log', 'cron.log', 'dmesg', 'lastlog', 'wtmp', 'btmp', 'messages', 'secure', 'maillog',
    'application.log', 'server.log', 'worker.log', 'queue.log', 'audit.log', 'events.log', 'metrics.log',
    // docs / misc
    'README.md', 'README.txt', 'CHANGELOG.md', 'LICENSE', 'NOTICE', 'TODO.md', 'NOTES.md', 'Makefile',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.dockerignore', 'VERSION', 'MANIFEST',
    'index.html', 'index.php', 'index.js', 'favicon.ico', 'robots.txt', 'sitemap.xml', 'humans.txt',
    'backup.sql', 'dump.sql', 'schema.sql', 'data.csv', 'export.csv', 'report.pdf', 'notes.txt', 'list.txt',
    'archive.tar.gz', 'backup.tar.gz', 'release.zip', 'package.tar', 'core.dump', 'nohup.out', 'output.txt',
    // more dotfiles / keys / certs
    '.bash_aliases', '.gitattributes', '.gitmodules', '.hushlogin', '.Xauthority', 'authorized_keys2',
    'id_ecdsa', 'id_ecdsa.pub', 'id_dsa', 'ssh_config', 'sshd_config', 'ca-certificates.crt', 'dhparam.pem',
    'server.crt', 'server.key', 'ssl-cert-snakeoil.pem', 'ssl-cert-snakeoil.key', 'privkey.pem', 'fullchain.pem',
    // system / proc-ish / service files
    'localtime', 'timezone', 'machine-id', 'mtab', 'mounts', 'cpuinfo', 'meminfo', 'loadavg', 'uptime',
    'version', 'cmdline', 'environment', 'shells', 'services', 'protocols', 'networks', 'nsswitch.conf',
    'ld.so.conf', 'ld.so.cache', 'inittab', 'rc.local', 'logrotate.conf', 'anacrontab', 'sysctl.conf',
    'limits.conf', 'login.defs', 'adduser.conf', 'lsb-release', 'timezone.conf', 'locale.conf', 'vconsole.conf',
];

$genericExts = ['txt', 'log', 'conf', 'cfg', 'ini', 'json', 'yaml', 'yml', 'xml', 'csv', 'md', 'bak',
    'tmp', 'old', 'sql', 'db', 'dat', 'gz', 'zip', 'tar', 'pem', 'key', 'crt', 'pdf', 'sh', 'lock'];

return [
    'generic' => ['dirs' => $genericDirs, 'files' => $genericFiles, 'exts' => $genericExts],

    'developer' => [
        'dirs' => ['src', 'lib', 'pkg', 'cmd', 'internal', 'api', 'apiv1', 'apiv2', 'graphql', 'grpc',
            'proto', 'schema', 'migrations', 'seeders', 'handlers', 'middleware', 'routes', 'controllers',
            'models', 'entities', 'repositories', 'dto', 'interfaces', 'contracts', 'events', 'listeners',
            'jobs', 'workers', 'queues', 'commands', 'console', 'tests', 'e2e', 'integration', 'unit',
            'mocks', 'stubs', 'fixtures', '__tests__', '__mocks__', 'coverage', 'ci', 'cd', '.github',
            '.gitlab', '.circleci', 'scripts', 'build', 'dist', 'target', 'node_modules', 'vendor',
            'venv', '.venv', 'env', 'site-packages', '__pycache__', '.pytest_cache', '.mypy_cache',
            '.tox', 'gradle', '.gradle', 'maven', '.m2', 'cargo', '.cargo', 'go', 'gopath'],
        'files' => ['main.go', 'main.py', 'main.rs', 'main.c', 'main.cpp', 'app.py', 'app.js', 'app.ts',
            'server.js', 'server.py', 'index.ts', 'index.tsx', 'package.json', 'package-lock.json',
            'yarn.lock', 'pnpm-lock.yaml', 'tsconfig.json', 'jsconfig.json', 'babel.config.js', '.eslintrc',
            '.prettierrc', 'webpack.config.js', 'vite.config.ts', 'rollup.config.js', 'requirements.txt',
            'requirements-dev.txt', 'setup.py', 'setup.cfg', 'pyproject.toml', 'Pipfile', 'Pipfile.lock',
            'poetry.lock', 'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'pom.xml', 'build.gradle',
            'settings.gradle', 'composer.json', 'composer.lock', 'Gemfile', 'Gemfile.lock', 'Rakefile',
            'Makefile', 'CMakeLists.txt', 'meson.build', '.env', '.env.example', 'jest.config.js',
            'pytest.ini', 'tox.ini', '.editorconfig', '.nvmrc', 'Dockerfile', 'Dockerfile.dev',
            'docker-compose.override.yml', 'deploy.sh', 'entrypoint.sh', 'run.sh', 'test.sh'],
        'exts' => ['go', 'py', 'js', 'ts', 'tsx', 'jsx', 'rs', 'c', 'cpp', 'h', 'java', 'kt', 'rb',
            'php', 'sql', 'sh', 'yaml', 'toml', 'lock', 'proto'],
    ],

    'finance' => [
        'dirs' => ['ledgers', 'ledger', 'gl', 'accounts', 'receivables', 'payables', 'ap', 'ar',
            'invoices', 'invoicing', 'billing', 'statements', 'reconciliation', 'reconciliations',
            'budgets', 'forecasts', 'forecasting', 'projections', 'reports', 'reporting', 'audits',
            'audit', 'tax', 'taxes', 'vat', 'payroll', 'expenses', 'expense-reports', 'receipts',
            'purchase-orders', 'po', 'quarterly', 'q1', 'q2', 'q3', 'q4', 'annual', 'monthly',
            'fy2023', 'fy2024', 'fy2025', 'closing', 'month-end', 'year-end', 'treasury', 'banking',
            'wire-transfers', 'ach', 'assets', 'liabilities', 'equity', 'depreciation', 'amortization'],
        'files' => ['general-ledger.xlsx', 'trial-balance.xlsx', 'balance-sheet.xlsx', 'income-statement.xlsx',
            'cash-flow.xlsx', 'p-and-l.xlsx', 'accounts-payable.csv', 'accounts-receivable.csv',
            'invoices-2024.csv', 'invoices-2025.csv', 'invoice-register.xlsx', 'expense-report.xlsx',
            'budget-2025.xlsx', 'forecast-q4.xlsx', 'reconciliation.xlsx', 'bank-statement.pdf',
            'wire-instructions.pdf', 'payroll-summary.xlsx', 'tax-return-2024.pdf', 'vat-return.xlsx',
            'audit-trail.csv', 'chart-of-accounts.csv', 'vendor-list.csv', 'customer-list.csv',
            'aging-report.xlsx', 'depreciation-schedule.xlsx', 'purchase-orders.csv', 'receipts-q3.zip',
            'closing-entries.xlsx', 'journal-entries.csv', 'fixed-assets.xlsx', 'cost-centers.csv'],
        'exts' => ['xlsx', 'xls', 'csv', 'pdf', 'docx', 'ods', 'xml', 'qbo', 'ofx'],
    ],

    'hr' => [
        'dirs' => ['employees', 'personnel', 'staff', 'onboarding', 'offboarding', 'recruiting',
            'recruitment', 'candidates', 'applications', 'resumes', 'cvs', 'interviews', 'offers',
            'contracts', 'agreements', 'policies', 'handbook', 'benefits', 'compensation', 'salaries',
            'payroll', 'timesheets', 'attendance', 'leave', 'vacation', 'pto', 'sick-leave', 'reviews',
            'performance', 'appraisals', 'training', 'certifications', 'compliance', 'grievances',
            'disciplinary', 'terminations', 'org-chart', 'departments', 'teams', 'directory', 'roster'],
        'files' => ['employee-directory.csv', 'org-chart.pdf', 'staff-roster.xlsx', 'salaries.xlsx',
            'compensation-bands.xlsx', 'payroll-2025.csv', 'timesheet-template.xlsx', 'leave-balances.xlsx',
            'employee-handbook.pdf', 'code-of-conduct.pdf', 'benefits-guide.pdf', 'offer-letter.docx',
            'employment-contract.docx', 'nda-template.docx', 'performance-review.docx', 'onboarding-checklist.pdf',
            'exit-interview.docx', 'headcount-plan.xlsx', 'candidate-pipeline.csv', 'interview-notes.docx',
            'training-records.csv', 'certifications.xlsx', 'emergency-contacts.csv', 'personnel-file.pdf'],
        'exts' => ['csv', 'xlsx', 'pdf', 'docx', 'doc', 'odt'],
    ],

    'sales' => [
        'dirs' => ['crm', 'leads', 'prospects', 'opportunities', 'pipeline', 'deals', 'accounts',
            'contacts', 'customers', 'clients', 'contracts', 'proposals', 'quotes', 'quotations',
            'orders', 'renewals', 'campaigns', 'marketing', 'collateral', 'presentations', 'demos',
            'territories', 'regions', 'quotas', 'commissions', 'forecasts', 'targets', 'reports',
            'win-loss', 'competitors', 'battlecards', 'pricing', 'discounts', 'partners', 'channel'],
        'files' => ['leads.csv', 'contacts.csv', 'accounts.csv', 'opportunities.csv', 'pipeline.xlsx',
            'sales-forecast.xlsx', 'quota-attainment.xlsx', 'commission-report.xlsx', 'deals-closed.csv',
            'proposal-template.docx', 'quote-template.xlsx', 'pricing-sheet.xlsx', 'discount-matrix.xlsx',
            'contract-template.docx', 'master-service-agreement.pdf', 'sow-template.docx', 'renewals-2025.csv',
            'win-loss-analysis.xlsx', 'competitor-battlecard.pdf', 'territory-plan.xlsx', 'campaign-results.csv',
            'sales-deck.pptx', 'demo-script.docx', 'customer-references.csv', 'crm-export.csv'],
        'exts' => ['csv', 'xlsx', 'pdf', 'docx', 'pptx', 'json'],
    ],

    'ops' => [
        'dirs' => ['ansible', 'terraform', 'terraform.d', 'playbooks', 'roles', 'inventory', 'k8s',
            'kubernetes', 'helm', 'charts', 'manifests', 'kustomize', 'overlays', 'base', 'clusters',
            'deployments', 'infra', 'infrastructure', 'provisioning', 'bootstrap', 'cloud-init', 'packer',
            'vagrant', 'docker', 'compose', 'registry', 'monitoring', 'prometheus', 'grafana', 'alertmanager',
            'loki', 'elk', 'logstash', 'kibana', 'nginx', 'haproxy', 'consul', 'vault', 'nomad', 'etcd',
            'certs', 'tls', 'secrets', 'backups', 'runbooks', 'sre', 'oncall', 'incidents', 'postmortems'],
        'files' => ['main.tf', 'variables.tf', 'outputs.tf', 'terraform.tfstate', 'terraform.tfvars',
            'provider.tf', 'backend.tf', 'playbook.yml', 'site.yml', 'inventory.ini', 'hosts.yml',
            'ansible.cfg', 'deployment.yaml', 'service.yaml', 'ingress.yaml', 'configmap.yaml',
            'secret.yaml', 'namespace.yaml', 'values.yaml', 'Chart.yaml', 'kustomization.yaml',
            'docker-compose.yml', 'prometheus.yml', 'alertmanager.yml', 'grafana.ini', 'nginx.conf',
            'haproxy.cfg', 'vault-config.hcl', 'consul.hcl', 'cloud-init.yaml', 'Vagrantfile',
            'deploy.sh', 'rollback.sh', 'healthcheck.sh', 'backup.sh', 'restore.sh', 'runbook.md'],
        'exts' => ['tf', 'tfvars', 'yaml', 'yml', 'hcl', 'ini', 'cfg', 'conf', 'sh', 'json', 'md'],
    ],
];
