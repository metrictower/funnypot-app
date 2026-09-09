<?php

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
    $GLOBALS['ingress_body_reads'] = 0;
    // Fixed telemetry only; this counter itself never copies target/header/body values.
    file_put_contents('/tmp/ingress/fpm-calls.log', "begin\n", FILE_APPEND | LOCK_EX);
    register_shutdown_function(static function (): void {
        $counts = ['body' => $GLOBALS['ingress_body_reads'],
            'geo' => (int) in_array('/app/demo/lib/geo.php', get_included_files(), true)];
        foreach (['config' => 'Funnypot\\App\\Config\\ConfigStore',
            'store' => 'Funnypot\\App\\Storage\\SqliteHitStore',
            'raw' => 'Funnypot\\App\\Storage\\RawCapture'] as $key => $class) {
            $counts[$key] = (int) class_exists($class, false);
        }
        file_put_contents('/tmp/ingress/fpm-calls.log', json_encode($counts) . "\n", FILE_APPEND | LOCK_EX);
        if ($counts['config'] === 1 && ($_SERVER['HTTP_X_INGRESS_CONTROL'] ?? '') === 'ingress-positive-header') {
            // Exercise PHP's configured error_log, separately from php://stderr/FPM capture.
            // Only the accepted positive request emits this fixed, target-free control.
            error_log('ingress-positive-php-error');
        }
    });
}
