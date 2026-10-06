<?php

declare(strict_types=1);

namespace Funnypot\App\Metrics;

/**
 * FP-0349 — renders funnypot's operator stats as a Prometheus text-format exposition with
 * OpenTelemetry-compatible metric names, for a Prometheus -> Grafana scrape.
 *
 * Pure + cheap: it takes the SAME bounded, already-computed arrays the dashboard feed uses
 * (HitStore::stats() + ::widgets()), so a scrape costs one stats query + one widgets query, never a
 * full hit-store scan. No I/O here — the caller supplies the arrays; this only formats.
 *
 * BOUNDED CARDINALITY is a hard requirement (a metrics surface with unbounded labels is both a
 * cardinality blow-up and a PII/fingerprint hazard): the only labelled series are per-template and
 * per-country, both already capped at the source (widgets() LIMIT 12). Raw source IPs (widgets()
 * 'talkers') are DELIBERATELY never emitted as labels.
 */
final class PrometheusMetricsRenderer
{
    private const PREFIX = 'funnypot_';

    /**
     * @param array<string,int|string> $stats   HitStore::stats() — total/detections/served/ips/harvested
     * @param array<string,mixed>      $widgets HitStore::widgets() — templates[], countries[] (bounded)
     */
    public function render(array $stats, array $widgets): string
    {
        $out = $this->scalar('events_total', 'counter', 'Total requests received by the honeypot.', $stats['total'] ?? 0)
            . $this->scalar('detections_total', 'counter', 'Requests detected as a scanner probe.', $stats['detections'] ?? 0)
            . $this->scalar('fakes_served_total', 'counter', 'Fake responses served to a probe.', $stats['served'] ?? 0)
            . $this->scalar('payloads_captured_total', 'counter', 'Requests carrying a captured body/payload.', $stats['harvested'] ?? 0)
            . $this->scalar('unique_source_ips', 'gauge', 'Distinct source IPs observed.', $stats['ips'] ?? 0);

        $out .= $this->labelled(
            'template_fired_total',
            'Matches per detection template (top ' . 12 . ', bounded).',
            'template',
            $this->pairs($widgets['templates'] ?? [], 't')
        );
        $out .= $this->labelled(
            'events_by_country_total',
            'Requests per source country (top 12, bounded).',
            'country',
            $this->pairs($widgets['countries'] ?? [], 'cc')
        );

        return $out;
    }

    /** One HELP/TYPE/value block for an unlabelled scalar. */
    private function scalar(string $name, string $type, string $help, $value): string
    {
        $metric = self::PREFIX . $name;

        return "# HELP {$metric} {$help}\n"
            . "# TYPE {$metric} {$type}\n"
            . $metric . ' ' . (int) $value . "\n";
    }

    /**
     * A labelled counter series. Empty $series emits the HELP/TYPE header only (a valid, scrapeable
     * zero-series — Prometheus tolerates a metric with no samples).
     *
     * @param array<string,int> $series label value => count
     */
    private function labelled(string $name, string $help, string $label, array $series): string
    {
        $metric = self::PREFIX . $name;
        $out = "# HELP {$metric} {$help}\n# TYPE {$metric} counter\n";
        foreach ($series as $value => $count) {
            $out .= $metric . '{' . $label . '="' . $this->escapeLabel((string) $value) . '"} ' . (int) $count . "\n";
        }

        return $out;
    }

    /**
     * Turn a widgets() row list ([{t|cc: string, n: int}, ...]) into a label=>count map, dropping
     * empty/blank keys. Bounded by the source LIMIT, so no extra cap needed here.
     *
     * @param mixed $rows
     * @return array<string,int>
     */
    private function pairs($rows, string $keyField): array
    {
        $out = [];
        if (!is_array($rows)) {
            return $out;
        }
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            $key = (string) ($row[$keyField] ?? '');
            if ($key === '') {
                continue;
            }
            $out[$key] = (int) ($row['n'] ?? 0);
        }

        return $out;
    }

    /** Escape a Prometheus label value: backslash, double-quote, newline (text-format rules). */
    private function escapeLabel(string $value): string
    {
        return str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $value);
    }
}
