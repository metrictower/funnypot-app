<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Metrics;

use Funnypot\App\Metrics\PrometheusMetricsRenderer;
use PHPUnit\Framework\TestCase;

final class PrometheusMetricsRendererTest extends TestCase
{
    private function stats(): array
    {
        return ['total' => 1234, 'detections' => 567, 'served' => 420, 'ips' => 88, 'harvested' => 12];
    }

    private function widgets(): array
    {
        return [
            'talkers' => [['ip' => '203.0.113.7', 'n' => 99, 'cc' => 'US']], // must NEVER become a label
            'countries' => [['cc' => 'US', 'n' => 500], ['cc' => 'CN', 'n' => 300]],
            'templates' => [['t' => 'attack-node-red', 'n' => 42], ['t' => 'nuclei-reflection', 'n' => 7]],
            'histogram' => [['h' => '2026-10-06T12', 'n' => 10]],
        ];
    }

    public function test_emits_the_scalar_counters_and_gauge_with_otel_names(): void
    {
        $out = (new PrometheusMetricsRenderer())->render($this->stats(), $this->widgets());
        self::assertStringContainsString("# TYPE funnypot_events_total counter\nfunnypot_events_total 1234\n", $out);
        self::assertStringContainsString("funnypot_detections_total 567\n", $out);
        self::assertStringContainsString("funnypot_fakes_served_total 420\n", $out);
        self::assertStringContainsString("funnypot_payloads_captured_total 12\n", $out);
        self::assertStringContainsString("# TYPE funnypot_unique_source_ips gauge\nfunnypot_unique_source_ips 88\n", $out);
    }

    public function test_labelled_template_and_country_series(): void
    {
        $out = (new PrometheusMetricsRenderer())->render($this->stats(), $this->widgets());
        self::assertStringContainsString('funnypot_template_fired_total{template="attack-node-red"} 42', $out);
        self::assertStringContainsString('funnypot_events_by_country_total{country="US"} 500', $out);
        self::assertStringContainsString('funnypot_events_by_country_total{country="CN"} 300', $out);
    }

    public function test_never_emits_a_raw_ip_label_cardinality_and_pii_hazard(): void
    {
        $out = (new PrometheusMetricsRenderer())->render($this->stats(), $this->widgets());
        self::assertStringNotContainsString('203.0.113.7', $out, 'raw source IPs must never appear as labels');
        self::assertStringNotContainsString('talker', $out);
    }

    public function test_bounded_cardinality_only_the_two_labelled_metrics(): void
    {
        $out = (new PrometheusMetricsRenderer())->render($this->stats(), $this->widgets());
        // Every labelled sample belongs to one of the two bounded metrics.
        foreach (explode("\n", $out) as $line) {
            if (strpos($line, '{') !== false) {
                self::assertMatchesRegularExpression(
                    '/^funnypot_(template_fired_total|events_by_country_total)\{/',
                    $line,
                    "unexpected labelled series: {$line}"
                );
            }
        }
    }

    public function test_escapes_label_values(): void
    {
        $widgets = ['templates' => [['t' => 'weird"name' . "\n" . 'x\\y', 'n' => 1]]];
        $out = (new PrometheusMetricsRenderer())->render($this->stats(), $widgets);
        self::assertStringContainsString('template="weird\\"name\\nx\\\\y"', $out);
    }

    public function test_empty_widgets_still_valid_exposition(): void
    {
        $out = (new PrometheusMetricsRenderer())->render(['total' => 0], []);
        self::assertStringContainsString("funnypot_events_total 0\n", $out);
        // Labelled metrics emit their HELP/TYPE header with no samples — valid + scrapeable.
        self::assertStringContainsString('# TYPE funnypot_template_fired_total counter', $out);
        self::assertStringNotContainsString('funnypot_template_fired_total{', $out);
    }

    public function test_values_are_integer_coerced(): void
    {
        $out = (new PrometheusMetricsRenderer())->render(['total' => '77'], ['templates' => [['t' => 'x', 'n' => '3']]]);
        self::assertStringContainsString("funnypot_events_total 77\n", $out);
        self::assertStringContainsString('funnypot_template_fired_total{template="x"} 3', $out);
    }
}
