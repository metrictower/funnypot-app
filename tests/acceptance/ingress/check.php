<?php

declare(strict_types=1);

require __DIR__ . '/Wire.php';

// Intentionally executable only in the isolated production-image job. No listener is opened here;
// the client can address only fixed loopback nginx/FPM ports. Every operation has an outer bound.
$started = hrtime(true);
$wire = new IngressWire();
$cases = [];
$rejectMarker = 'ingress-reject-7b6e4d';
$body414 = '<!doctype html><title>414 URI Too Long</title>URI Too Long';
$check = static function (bool $ok, string $name): void {
    if (!$ok) {
        throw new RuntimeException($name);
    }
};
$calls = static function (): int {
    return substr_count((string) file_get_contents('/tmp/ingress/fpm-calls.log'), "begin\n");
};
$save = static function (string $label, array $response, int $before, int $after) use (&$cases): void {
    $cases[] = ['case' => $label, 'status' => $response['status'], 'body_bytes' => strlen($response['body']),
        'fpm_delta' => $after - $before, 'elapsed_ms' => $response['elapsed_ms']];
};
$assert414 = static function (array $response) use ($check, $body414): void {
    $check($response['status'] === 414 && $response['body'] === $body414, 'fixed-414-status-body');
    foreach (['content-type' => 'text/html; charset=UTF-8', 'cache-control' => 'no-store',
        'connection' => 'close'] as $key => $value) {
        $check(($response['headers'][$key] ?? []) === [$value], 'fixed-414-header-' . $key);
    }
};
$snapshot = static function (): array {
    $out = [];
    foreach (['/app/demo/storage', '/tmp/ingress', '/var/log/nginx'] as $dir) {
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $file) {
            if ($file->isFile() && !$file->isLink()) {
                // Bound scans too. All fixture stores/logs together must fit this small workload.
                if ($file->getSize() > 16 * 1024 * 1024 || count($out) >= 128) {
                    throw new RuntimeException('sink-scan-budget');
                }
                $out[$file->getPathname()] = (string) file_get_contents($file->getPathname());
            }
        }
    }
    if (array_sum(array_map('strlen', $out)) > 48 * 1024 * 1024) {
        throw new RuntimeException('sink-total-budget');
    }
    return $out;
};

try {
    $check(is_file('/.dockerenv') && is_dir('/evidence') && is_file('/app/demo/index.php'), 'isolated-image-required');
    $wire->awaitReady();
    // A real accepted hit independently exercises each sink before any negative claims. No drain
    // worker exists, no real key is configured, and container network=none forbids external delivery.
    $control = $wire->http(80, 'public.ingress.invalid', 'GET', '/.env?ingress-positive-query', 1,
        '', ['X-Forwarded-For' => '192.0.2.13', 'X-Ingress-Control' => 'ingress-positive-header',
            'User-Agent' => 'ingress-positive-agent']);
    $check($control['status'] < 500 && $calls() === 1, 'accepted-positive-bootstrap');
    $db = new PDO('sqlite:/app/demo/storage/funnypot.sqlite');
    $check((int) $db->query('SELECT COUNT(*) FROM hits')->fetchColumn() > 0, 'positive-hit-row');
    $check((int) $db->query('SELECT MAX(length(path)) FROM hits')->fetchColumn() <= 400, 'hit-path-cap');
    $raw = new PDO('sqlite:/app/demo/storage/raw-capture.sqlite');
    $check((int) $raw->query('SELECT COUNT(*) FROM raw_requests')->fetchColumn() > 0, 'positive-raw-row');
    $intel = new PDO('sqlite:/app/demo/storage/intel.sqlite');
    foreach (['abuse_queue', 'ti_queue'] as $table) {
        $check((int) $intel->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn() > 0, 'positive-' . $table);
    }
    $check(str_contains((string) file_get_contents('/app/demo/storage/hits.log'), 'ingress-positive-agent'), 'positive-export-record');
    // FPM catch_workers_output receives SqliteHitStore's php://stderr record, independently of
    // error_log and access logging. Inspect the actual destination, not just a created filename.
    $check(str_contains((string) file_get_contents('/tmp/ingress/fpm-error.log'), 'ingress-positive-agent'), 'positive-php-stderr-record');
    $check(str_contains((string) file_get_contents('/tmp/ingress/fpm-access.log'), 'ingress-fpm-request'), 'positive-fpm-access');
    foreach (['config', 'store', 'raw', 'geo'] as $field) {
        $check(str_contains((string) file_get_contents('/tmp/ingress/fpm-calls.log'), '"' . $field . '":1'), 'positive-' . $field . '-spy');
    }
    // nginx request logging is intentionally disabled, not a sink falsely claimed exercised.
    // Startup/config diagnostics have their own positive control from nginx -t / startup.
    $check(str_contains((string) file_get_contents('/evidence/nginx-config-test.log'), 'test is successful'), 'positive-nginx-config-diagnostic');
    $save('accepted-sinks', $control, 0, $calls());
    $before = $calls();
    $control = $wire->http(80, 'public.ingress.invalid', 'POST', '/ingress-body-control', 1, 'ingress-positive-body');
    $check($calls() === $before + 1 && str_contains((string) file_get_contents('/tmp/ingress/fpm-calls.log'), '"body":1'), 'positive-body-spy');
    $save('accepted-body-read', $control, $before, $calls());

    $vhosts = [[80, 'public.ingress.invalid'], [443, 'public.ingress.invalid'],
        [80, 'admin.ingress.invalid'], [443, 'admin.ingress.invalid']];
    foreach ($vhosts as [$port, $host]) {
        foreach ([1, 2, 16] as $spaces) {
            foreach ([4095, 4096, 4097] as $bytes) {
                foreach (['origin', 'absolute'] as $form) {
                    $path = '/robots.txt';
                    $target = $form === 'origin'
                        ? str_pad($path . '?' . ($bytes > 4096 ? $rejectMarker : 'control'), $bytes, 'q')
                        : 'http://' . str_pad($bytes > 4096 ? $rejectMarker : 'control', $bytes - 7 - strlen($path), 'a') . $path;
                    $check(strlen($target) === $bytes, 'fixture-target-length');
                    $before = $calls();
                    $response = $wire->http($port, $host, 'GET', $target, $spaces);
                    $after = $calls();
                    if ($bytes > 4096) {
                        $assert414($response);
                        $check($after === $before, 'edge-no-fpm');
                    } else {
                        $check($response['status'] === 200 && $after === $before + 1, 'exact-target-reaches-real-route');
                    }
                    $save("target-$port-$host-$spaces-$bytes-$form", $response, $before, $after);
                }
            }
        }
        foreach ([4096, 4097] as $bytes) {
            $target = str_pad('/.well-known/acme-challenge/ingress-token?' . ($bytes > 4096 ? $rejectMarker : 'control'), $bytes, 'q');
            $before = $calls();
            $response = $wire->http($port, $host, 'GET', $target);
            $check($calls() === $before, 'acme-never-fpm');
            $bytes > 4096 ? $assert414($response) : $check($response['status'] === 200
                && $response['body'] === 'ingress-acme-control', 'exact-acme-token');
            $save("acme-$port-$host-$bytes", $response, $before, $calls());
        }
        foreach (['%41', '%2541', '%00', '%', 'é', "\xff", '??&&//../'] as $encoding) {
            foreach ([4096, 4097] as $bytes) {
                $target = str_pad('/robots.txt?' . $encoding . ($bytes > 4096 ? $rejectMarker : 'control'), $bytes, 'q');
                $before = $calls();
                $response = $wire->http($port, $host, 'GET', $target);
                if ($bytes > 4096) {
                    $assert414($response);
                    $check($calls() === $before, 'encoding-edge-no-fpm');
                } else {
                    $check($response['status'] === 200 && $calls() === $before + 1, 'encoding-normal-bootstrap');
                }
                $save("encoding-$port-$host-$bytes-" . bin2hex($encoding), $response, $before, $calls());
            }
        }
        foreach (['line', 'header'] as $kind) {
            $before = $calls();
            $target = $kind === 'line' ? str_pad('/' . $rejectMarker, 12000, 'q') : '/robots.txt';
            $headers = $kind === 'header' ? ['X-Ingress-Control' => str_pad($rejectMarker, 12000, 'q')] : [];
            $response = $wire->http($port, $host, 'GET', $target, 1, '', $headers);
            $check($response['status'] >= 400 && $response['status'] < 500
                && strlen($response['body']) <= 2048 && !str_contains($response['body'], $rejectMarker), 'gross-bounded-4xx');
            $check($calls() === $before, 'gross-no-fpm');
            $save("gross-$port-$host-$kind", $response, $before, $calls());
        }
        foreach (['line', 'header'] as $kind) {
            $before = $calls();
            $bytes = $kind === 'line' ? 'GET /' . $rejectMarker
                : "GET /robots.txt HTTP/1.1\r\nHost: $host\r\nX-Ingress-Control: $rejectMarker";
            $response = $wire->partial($port, $host, $bytes);
            $check($response['elapsed_ms'] >= 4000 && $response['elapsed_ms'] <= 7500, 'partial-five-second-deadline');
            $check($response['status'] === 0 || $response['status'] === 408, 'partial-close-or-408');
            $check(strlen($response['body']) <= 128 && !str_contains($response['body'], $rejectMarker), 'partial-target-free');
            $check($calls() === $before, 'partial-no-fpm');
            $save("partial-$port-$host-$kind", $response, $before, $calls());
        }
    }
    $before = $calls();
    $timeout = $wire->partial(8099, 'ingress-probe.invalid',
        "POST /__ingress_body_timeout HTTP/1.1\r\nHost: ingress-probe.invalid\r\nContent-Length: 10\r\n\r\nx");
    $check($timeout['status'] === 408 && $timeout['body'] === "Request Timeout\n", 'special-response-408-body');
    foreach (['content-type' => 'text/plain; charset=utf-8', 'cache-control' => 'no-store', 'connection' => 'close'] as $key => $value) {
        $check(($timeout['headers'][$key] ?? []) === [$value], 'special-response-408-' . $key);
    }
    $check($calls() === $before, 'body-timeout-no-fpm');
    $save('special-response-408-not-header-timeout', $timeout, $before, $calls());

    // Direct FastCGI bypass proves the PHP defense in depth in the actual FPM SAPI, with every
    // optional sink still armed. Only the fixed begin/end observer is permitted to run.
    $before = $calls();
    $response = $wire->fastcgi(str_pad('/.env?' . $rejectMarker, 4097, 'q'), $rejectMarker,
        ['HTTP_X_INGRESS_CONTROL' => $rejectMarker]);
    $assert414($response);
    $check($calls() === $before + 1, 'direct-fpm-positive-entry');
    $log = trim((string) file_get_contents('/tmp/ingress/fpm-calls.log'));
    $last = json_decode(substr($log, strrpos($log, "\n") + 1), true);
    $check($last === ['body' => 0, 'geo' => 0, 'config' => 0, 'store' => 0, 'raw' => 0], 'direct-no-bootstrap');
    $save('direct-fpm-4097', $response, $before, $calls());

    foreach ($snapshot() as $path => $bytes) {
        $check(!str_contains($bytes, $rejectMarker), 'negative-sentinel-in-sink-' . basename($path));
    }
    file_put_contents('/evidence/receipt.json', json_encode(['status' => 'passed',
        'elapsed_ms' => (hrtime(true) - $started) / 1e6, 'cases' => $cases,
        'sink_controls' => ['hits', 'raw_requests', 'hits.log', 'abuse_queue', 'ti_queue',
            'PHP stderr', 'FPM access', 'FPM admission/body/bootstrap counters', 'nginx config diagnostics'],
        'nginx_request_logs' => 'disabled by production policy; not falsely counted as positive sinks',
    ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
    echo "Input ceiling real-image acceptance passed\n";
} catch (Throwable $error) {
    file_put_contents('/evidence/receipt.json', json_encode(['status' => 'failed',
        'failed_check' => $error->getMessage(), 'cases' => $cases], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
    fwrite(STDERR, 'Input ceiling acceptance failed: ' . $error->getMessage() . "\n");
    exit(1);
}
