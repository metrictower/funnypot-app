<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\S7comm;

use Funnypot\Protocol\S7comm\S7commConfig;
use Funnypot\Protocol\S7comm\S7commServer;
use Funnypot\Protocol\S7comm\S7commSession;
use PHPUnit\Framework\TestCase;

final class S7commReconLoggingTest extends TestCase
{
    use S7commTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * A server + a session already past the COTP handshake, ready for S7comm PDUs.
     *
     * @return array{0:S7commServer,1:S7commSession}
     */
    private function connected(?S7commConfig $config = null): array
    {
        $this->events = [];
        $server = new S7commServer($config ?? new S7commConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new S7commSession('198.51.100.20', 33000, 1);
        $session->inbuf .= self::connectionRequest();
        $server->processInbound($session);
        $session->outbuf = '';

        return [$server, $session];
    }

    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }

    public function test_szl_module_identification_returns_order_number(): void
    {
        [$server, $session] = $this->connected();

        $session->inbuf .= self::readSzl(0x0011);
        $server->processInbound($session);

        $szl = $this->eventOfType('s7_szl');
        self::assertNotNull($szl);
        self::assertSame('0x0011', $szl['szl_id']);
        self::assertStringContainsString('Module identification', $szl['path']);
        self::assertSame(['id' => 0x0011, 'index' => 0x0000], $session->szlReads[0]);

        // Response is a Userdata PDU (ROSCTR 0x07) carrying the module order number.
        self::assertSame(0x07, ord($session->outbuf[8]));
        self::assertStringContainsString('6ES7 214-1AG40-0XB0', $session->outbuf);
    }

    public function test_szl_component_identification_returns_cpu_identity(): void
    {
        [$server, $session] = $this->connected();

        $session->inbuf .= self::readSzl(0x001C);
        $server->processInbound($session);

        $szl = $this->eventOfType('s7_szl');
        self::assertNotNull($szl);
        self::assertSame('0x001C', $szl['szl_id']);

        // The component identity strings a scanner fingerprints on.
        self::assertStringContainsString('CPU 1214C DC/DC/DC', $session->outbuf);
        self::assertStringContainsString('Original Siemens Equipment', $session->outbuf);
        self::assertStringContainsString('S7-1200 station_1', $session->outbuf);
    }

    public function test_s7_300_profile_serves_a_different_identity(): void
    {
        $config = new S7commConfig(
            orderNumber: '6ES7 315-2EH14-0AB0',
            moduleTypeName: 'CPU 315-2 PN/DP',
            systemName: 'SIMATIC 300 station'
        );
        [$server, $session] = $this->connected($config);

        $session->inbuf .= self::readSzl(0x0011);
        $server->processInbound($session);
        self::assertStringContainsString('6ES7 315-2EH14-0AB0', $session->outbuf);

        $session->outbuf = '';
        $session->inbuf .= self::readSzl(0x001C);
        $server->processInbound($session);
        self::assertStringContainsString('CPU 315-2 PN/DP', $session->outbuf);
    }

    public function test_read_var_captures_marker_area_recon(): void
    {
        [$server, $session] = $this->connected();

        // Read of M (flags) area, byte 20, 4 bytes.
        $session->inbuf .= self::readVar(transport: 0x02, count: 4, db: 0, area: 0x83, byte: 20);
        $server->processInbound($session);

        self::assertSame(0x83, $session->reads[0]['area']);
        self::assertSame(20, $session->reads[0]['byte']);

        $job = $this->eventOfType('s7_job');
        self::assertNotNull($job);
        self::assertSame('read', $job['function']);
        self::assertSame('high', $job['severity']);
        self::assertStringContainsString('M20', $job['path']);
    }

    public function test_write_var_is_captured_but_inert(): void
    {
        [$server, $session] = $this->connected();

        // Write 2 bytes to DB5 at byte 0 — must be logged, acknowledged as success, never applied.
        $session->inbuf .= self::writeVar(transport: 0x02, count: 2, db: 5, area: 0x84, byte: 0, value: "\xde\xad");
        $server->processInbound($session);

        self::assertSame('write', $session->reads[0]['op']);
        self::assertSame(5, $session->reads[0]['db']);

        $job = $this->eventOfType('s7_job');
        self::assertNotNull($job);
        self::assertSame('write', $job['function']);
        self::assertStringContainsString('inert', $job['path']);

        // Write response: Ack_Data, function 0x05, one success byte (0xFF) per item.
        $resp = $session->outbuf;
        self::assertSame(0x03, ord($resp[8]), 'ROSCTR Ack_Data');
        self::assertSame(0x05, ord($resp[19]), 'Write Var function echoed');
        self::assertSame(0xff, ord($resp[21]), 'per-item success return code');
    }

    public function test_unknown_job_function_is_logged_without_closing(): void
    {
        [$server, $session] = $this->connected();

        // Function 0x1A (block/PI functions) is unmodelled: record it but keep serving later probes.
        $param = "\x1a\x00";
        $job = self::cotpData(self::s7Header(0x01, 0x0500, strlen($param), 0) . $param);
        $session->inbuf .= $job;
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('s7_unknown'));
        self::assertFalse($session->close);
        self::assertSame('', $session->outbuf);
    }

    public function test_unknown_userdata_funcgroup_is_recorded(): void
    {
        [$server, $session] = $this->connected();

        // Userdata with funcgroup 0x1 (not CPU functions) is out of scope: record only.
        $param = "\x00\x01\x12\x04\x11\x41\x01\x00"; // type|funcgroup = 0x41
        $ud = self::cotpData(self::s7Header(0x07, 0x0600, strlen($param), 0) . $param);
        $session->inbuf .= $ud;
        $server->processInbound($session);

        $unknown = $this->eventOfType('s7_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('funcgroup=0x1', $unknown['path']);
    }

    public function test_every_event_carries_the_s7comm_envelope(): void
    {
        [$server, $session] = $this->connected();

        $session->inbuf .= self::setupCommunication();
        $server->processInbound($session);
        $session->inbuf .= self::readSzl(0x0011);
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('s7comm', $e['proto']);
            self::assertSame('S7COMM', $e['method']);
            self::assertSame(1, $e['matched']);
            self::assertSame(1, $e['served']);
            self::assertArrayHasKey('ts', $e);
            self::assertArrayHasKey('severity', $e);
            self::assertArrayHasKey('event', $e);
            self::assertArrayHasKey('ip', $e);
            self::assertArrayHasKey('port', $e);
            self::assertArrayHasKey('path', $e);
        }
    }

    public function test_parse_var_items_decodes_multiple_s7any_addresses(): void
    {
        // Job param: function 0x04, item count 2, two S7ANY specs (DB1 byte 0, and inputs I byte 4 bit 2).
        $param = "\x04\x02"
            . self::s7AnyItem(0x04, 1, 1, 0x84, 0)   // DB1.DBW0
            . self::s7AnyItem(0x01, 1, 0, 0x81, 4, 2); // I4.2 (bit)

        $items = S7commServer::parseVarItems($param);
        self::assertCount(2, $items);

        self::assertSame(0x84, $items[0]['area']);
        self::assertSame(1, $items[0]['db']);
        self::assertSame(0x04, $items[0]['transport']);

        self::assertSame(0x81, $items[1]['area']);
        self::assertSame(4, $items[1]['byte']);
        self::assertSame(2, $items[1]['bit']);
    }

    public function test_area_name_mapping(): void
    {
        self::assertSame('DB', S7commServer::areaName(0x84));
        self::assertSame('M', S7commServer::areaName(0x83));
        self::assertSame('I', S7commServer::areaName(0x81));
        self::assertSame('Q', S7commServer::areaName(0x82));
    }

    public function test_config_from_env_selects_profile_and_overrides(): void
    {
        putenv('FUNNYPOT_S7COMM_PROFILE=s7-300');
        $config = S7commConfig::fromEnv();
        self::assertSame('6ES7 315-2EH14-0AB0', $config->orderNumber);
        self::assertSame('CPU 315-2 PN/DP', $config->moduleTypeName);

        putenv('FUNNYPOT_S7COMM_SYSTEM_NAME=PLANT-A-CTRL');
        $config = S7commConfig::fromEnv();
        self::assertSame('PLANT-A-CTRL', $config->systemName);

        putenv('FUNNYPOT_S7COMM_PROFILE');
        putenv('FUNNYPOT_S7COMM_SYSTEM_NAME');

        // Default profile is the S7-1200.
        $config = S7commConfig::fromEnv();
        self::assertSame('6ES7 214-1AG40-0XB0', $config->orderNumber);
    }
}
