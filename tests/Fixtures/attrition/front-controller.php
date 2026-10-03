<?php

declare(strict_types=1);

// Pure CLI fixture: execute the real composition root, never start a server or replace a production class.
$_SERVER = [
    'REQUEST_METHOD' => $argv[1], 'REQUEST_URI' => $argv[2], 'REMOTE_ADDR' => '192.0.2.13',
    'HTTP_HOST' => 'example.test', 'HTTP_USER_AGENT' => 'integration-fixture', 'SERVER_PORT' => '80',
    'SERVER_PROTOCOL' => 'HTTP/1.1',
];
$_GET = $_POST = $_COOKIE = $_FILES = [];
http_response_code(200);
ob_start();
require dirname(__DIR__, 3) . '/demo/index.php';
$body = (string) ob_get_clean();
$entry = null;
if (preg_match_all('~<code>([A-Za-z0-9+/=]+)</code>~', $body, $matches)) {
    foreach ($matches[1] as $encoded) {
        $decoded = base64_decode($encoded, true);
        if (is_string($decoded) && str_starts_with($decoded, '/admin/export/jobs/at1.e.')) {
            $entry = $decoded;
        }
    }
}
$sharedBudget = false;
if ($attrition !== null && $labyrinth !== null && $polluter !== null) {
    $sharedBudget = true;
    foreach ([$attrition, $labyrinth, $polluter] as $controller) {
        $sharedBudget = $sharedBudget && (new ReflectionProperty($controller, 'budget'))->getValue($controller) === $tarpitBudget;
    }
}
$job = json_decode($body, true);
echo json_encode([
    'status' => http_response_code(), 'profile' => isset($effectiveServiceProfile) ? $effectiveServiceProfile->baseFamily() : null,
    'attrition' => $attrition !== null, 'shared_budget' => $sharedBudget, 'entry' => $entry,
    'job_schema' => is_array($job) ? ($job['schema'] ?? null) : null,
    'job_state' => is_array($job) ? ($job['state'] ?? null) : null,
    'body_bytes' => strlen($body),
], JSON_THROW_ON_ERROR), "\n";
