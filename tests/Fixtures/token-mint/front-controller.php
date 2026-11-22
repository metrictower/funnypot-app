<?php

declare(strict_types=1);

// Pure CLI fixture: execute the real composition root for one GET and report whether the token-mint
// surface was wired, never start a server or replace a production class.
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
echo json_encode([
    'status' => http_response_code(),
    'wired' => isset($tokenMint) && $tokenMint !== null,
    'front' => isset($accountFront) && $accountFront !== null,
    'body' => $body,
], JSON_THROW_ON_ERROR), "\n";
