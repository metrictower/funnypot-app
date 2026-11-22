<?php

declare(strict_types=1);

// The SSRF bench in a PHP started with every network-capable function disabled, URL wrappers off and a
// dead sendmail. It first checks that every function the parent listed in SSRF_DISABLED is really gone,
// runs an optional planted positive control (SSRF_CHILD_PLANT), then the bench, and prints one JSON line.
// No shell, no exec: the parent owns the temp directory and its cleanup.

$root = dirname(__DIR__, 5);
require $root . '/tests/bootstrap.php';
foreach (glob($root . '/tests/App/Identity/*.php') ?: [] as $f) {
    require_once $f;
}
require_once $root . '/demo/lib/geo.php';
require_once $root . '/scripts/support/SsrfPivotCrawler.php';

$out = ['steps' => 0, 'faults' => 0, 'errors' => 0, 'warnings' => 0, 'transcript_hash' => '', 'still_defined' => [], 'checked' => 0, 'unexpected_extensions' => [], 'class_clients' => false];
foreach (array_filter(explode(',', (string) getenv('SSRF_DISABLED'))) as $fn) {
    $out['checked']++;
    if (function_exists($fn)) {
        $out['still_defined'][] = $fn;
    }
}
$out['unexpected_extensions'] = array_values(array_diff(get_loaded_extensions(), array_filter(explode(',', (string) getenv('SSRF_EXTENSIONS')))));
$out['class_clients'] = extension_loaded('redis') || extension_loaded('openswoole') || extension_loaded('swoole') || extension_loaded('memcached') || extension_loaded('mongodb') || extension_loaded('amqp');
set_error_handler(static function (int $no, string $msg) use (&$out): bool {
    if ((error_reporting() & $no) !== 0 && !str_contains($msg, 'headers already sent')) {
        $out['warnings']++;
        $out['last_warning'] = substr($msg, 0, 160);
    }

    return true;
});
try {
    switch ((string) getenv('SSRF_CHILD_PLANT')) {
        case 'curl':
            curl_init();
            break;
        case 'url':
            file_get_contents('http://x.invalid/');
            break;
        case 'stat':
            file_exists('ftp://x.invalid/a');
            break;
        default:
            $c = new Funnypot\App\Bench\SsrfPivotCrawler();
            $r = $c->run((int) (getenv('SSRF_CHILD_STEPS') ?: 300));
            $out['steps'] = $r['steps'];
            $out['faults'] = $r['faults'];
            $out['transcript_hash'] = $r['transcript_hash'];
            $c->cleanup();
    }
} catch (Throwable $e) {
    $out['errors']++;
    $out['error'] = get_class($e) . ': ' . substr($e->getMessage(), 0, 160);
}
echo json_encode($out), "\n";
