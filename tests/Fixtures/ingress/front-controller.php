<?php

// Test-only, socket-free entry into the UNMODIFIED production front controller. The environment
// and all writable paths are supplied by the parent; no deployed data or external service is used.
declare(strict_types=1);

namespace Funnypot\Core {
    function file_get_contents(string $path, ...$args)
    {
        if ($path === 'php://input') {
            ++$GLOBALS['ingress_body_reads'];
        }
        return \file_get_contents($path, ...$args);
    }
}

namespace {
    $root = dirname(__DIR__, 3);
    require $root . '/vendor/autoload.php';
    $target = base64_decode($argv[1], true);
    $fault = $argv[2];
    $data = getenv('FUNNYPOT_TEST_INGRESS_DATA');
    if (!is_string($target) || !is_string($data) || !is_dir($data)) {
        exit(2);
    }
    // A minimal test-owned web bundle exercises the real reader, without invoking the root
    // preparer, generating a TLS certificate, changing UID/GID or installing a service profile.
    $deriver = \Funnypot\App\Identity\IdentityKeyDeriver::fromMaster(hash('sha256', 'ingress-fixture', true));
    $identity = \Funnypot\App\Identity\HttpIdentity::fromDeriver($deriver, 'ingress-fixture');
    mkdir($data . '/runtime', 0700);
    mkdir($data . '/runtime/identity-http', 0700);
    file_put_contents($data . '/runtime/identity-http/http.json', json_encode([
        'envelope' => [
            'schema' => \Funnypot\App\Identity\IdentityBundleReader::SCHEMA,
            'bundle' => 'http', 'source' => 'fixture', 'public_persona_hash' => 'fixture',
            'keyset_commitment' => 'fixture',
        ],
        'payload' => $identity->toPayload(),
    ], JSON_THROW_ON_ERROR));
    chmod($data . '/runtime/identity-http/http.json', 0600);
    $_SERVER = [
        'REQUEST_URI' => $target, 'REQUEST_METHOD' => $argv[3], 'SERVER_PORT' => '80',
        'REMOTE_ADDR' => '192.0.2.13', 'HTTP_HOST' => 'example.invalid',
        'HTTP_USER_AGENT' => 'ingress-boundary-control', 'HTTP_X_INGRESS_CONTROL' => 'header-control',
    ];
    $_GET = $_POST = $_COOKIE = [];
    $shape = $argv[4] ?? 'string';
    $nonStrings = ['null' => null, 'false' => false, 'true' => true,
        'integer' => 4097, 'array' => [], 'object' => new \stdClass()];
    if ($shape === 'missing') {
        unset($_SERVER['REQUEST_URI']);
    } elseif (array_key_exists($shape, $nonStrings)) {
        $_SERVER['REQUEST_URI'] = $nonStrings[$shape];
    } elseif ($shape !== 'string') {
        exit(2);
    }
    http_response_code(200); // CGI's default, otherwise the CLI-only getter starts at false.
    $classes = [];
    $GLOBALS['ingress_body_reads'] = 0;
    spl_autoload_register(static function (string $class) use (&$classes, $fault, $target): void {
        $classes[] = $class;
        if ($class === 'Funnypot\\App\\Http\\EarlyIngressGuard') {
            if ($fault === 'throw') {
                throw new \RuntimeException('guard-fault-' . $target);
            }
            if ($fault === 'fatal') {
                trigger_error('guard-fault-' . $target, E_USER_ERROR);
            }
        }
    }, true, true);
    ob_start(static function (string $body) use (&$classes, $root): string {
        return json_encode([
            'status' => http_response_code(), 'body' => base64_encode($body),
            'classes' => $classes, 'body_reads' => $GLOBALS['ingress_body_reads'],
            'geo_included' => in_array($root . '/demo/lib/geo.php', get_included_files(), true),
            'target_is_slash' => ($_SERVER['REQUEST_URI'] ?? null) === '/',
        ], JSON_THROW_ON_ERROR);
    });
    require $root . '/demo/index.php';
}
