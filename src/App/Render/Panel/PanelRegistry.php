<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

/**
 * Module -> PanelSection dispatch for the deep admin dashboard (design ruling R2). The skin parses a
 * route, normalises the module slug through the alias table, and asks the registry for the section to
 * render — so adding a module is registering one more class here, never another switch arm in the skin.
 *
 * An unknown or empty module falls back to the Dashboard (a 404 inside a deep panel is itself a tell:
 * spec §B.1). Aliases keep every legacy sidebar slug reachable after the migration off last-segment
 * routing (e.g. `system-info` and `api-keys` still resolve).
 */
final class PanelRegistry
{
    /** @var array<string,PanelSection> module slug (canonical) => section */
    private $sections;

    /** @var array<string,string> alias slug => canonical module slug */
    private $aliases;

    /** @var PanelSection */
    private $fallback;

    public function __construct()
    {
        $dashboard = new DashboardSection();
        $databases = new DatabasesSection();
        $this->sections = [
            'dashboard' => $dashboard,
            'system' => new SystemSection(),
            'databases' => $databases,
            'users' => $databases,   // the users loot table is a Databases drill-down (T1 fix)
            'backups' => new BackupsSection(),
            'keys' => new KeysSection(),
            'cron' => new CronSection(),
            'processes' => new ProcessesSection(),
            'logs' => new LogsSection(),
            'files' => new FilesSection(),
            'access' => new AccessSection(),
            'fire' => new FireSection(),
            'cctv' => new CctvSection(),
            'hvac' => new HvacSection(),
            'hr' => new HrSection(),
            'finance' => new FinanceSection(),
            'bank' => new BankSection(),
            'vendors' => new VendorsSection(),
            'lighting' => new LightingSection(),
            'appliances' => new AppliancesSection(),
            'sensors' => new SensorsSection(),
            'energy' => new EnergySection(),
            'it' => new ItAssetsSection(),
            'network' => new NetworkSection(),
            'helpdesk' => new ItServicesSection(),
            'facilities' => new FacilitiesSection(),
        ];
        $this->aliases = [
            '' => 'dashboard', 'home' => 'dashboard', 'overview' => 'dashboard',
            'system-info' => 'system', 'servers' => 'system', 'server' => 'system',
            'database' => 'databases', 'db' => 'databases',
            'backup' => 'backups',
            'api-keys' => 'keys', 'tokens' => 'keys', 'secrets' => 'keys',
            'jobs' => 'cron',
            'ps' => 'processes',
            'log' => 'logs',
            'filemanager' => 'files', 'file' => 'files',
            'doors' => 'access', 'badges' => 'access', 'acs' => 'access',
            'security' => 'fire', 'safety' => 'fire', 'alarms' => 'fire', 'life-safety' => 'fire',
            'cameras' => 'cctv', 'camera' => 'cctv', 'nvr' => 'cctv', 'video' => 'cctv',
            'climate' => 'hvac', 'bms' => 'hvac', 'building' => 'hvac',
            'employees' => 'hr', 'people' => 'hr', 'staff' => 'hr',
            'invoices' => 'finance', 'ap' => 'finance', 'accounts-payable' => 'finance',
            'treasury' => 'bank', 'banking' => 'bank',
            'suppliers' => 'vendors', 'payments' => 'vendors',
            'lights' => 'lighting', 'covers' => 'lighting', 'blinds' => 'lighting',
            'coffee' => 'appliances', 'elevator' => 'appliances', 'av' => 'appliances',
            'environment' => 'sensors', 'climate-sensors' => 'sensors',
            'power' => 'energy', 'metering' => 'energy',
            'cmdb' => 'it', 'assets' => 'it', 'inventory' => 'it', 'integrations' => 'it', 'devices' => 'it',
            'vpn' => 'network', 'voip' => 'network', 'telephony' => 'network',
            'tickets' => 'helpdesk', 'printers' => 'helpdesk', 'licenses' => 'helpdesk',
            'mdm' => 'helpdesk', 'mail' => 'helpdesk', 'certificates' => 'helpdesk',
            'floorplan' => 'facilities', 'rooms' => 'facilities', 'work-orders' => 'facilities',
            'workorders' => 'facilities', 'meeting-rooms' => 'facilities', 'bookings' => 'facilities',
        ];
        $this->fallback = $dashboard;
    }

    /** The section for a (possibly aliased) module slug; the Dashboard for anything unmapped. */
    public function sectionFor(string $module): PanelSection
    {
        $canonical = $this->aliases[$module] ?? $module;
        return $this->sections[$canonical] ?? $this->fallback;
    }

    /** True when the module slug maps to a real section (not the unknown-module fallback). */
    public function has(string $module): bool
    {
        $canonical = $this->aliases[$module] ?? $module;
        return isset($this->sections[$canonical]);
    }
}
