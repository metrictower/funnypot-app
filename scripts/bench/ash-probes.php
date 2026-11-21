<?php

declare(strict_types=1);

// Lists every payload the golden capture runs, one per line: kind <TAB> key <TAB> base64(payload).
// kind "error": run through `sh -c` and record the first stderr line (AshVocabulary::goldenProbes()).
// kind "parse": run through `sh -n -c` (parse only, never executes) and record rc + first stderr line
// (the ShellLexer cases in tests/Fixtures/cmdi/lexer-cases.php).

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Funnypot\App\Tarpit\Cmdi\AshVocabulary;

foreach (AshVocabulary::goldenProbes() as $key => [$payload]) {
    echo "error\t{$key}\t" . base64_encode($payload) . "\n";
}
foreach (require dirname(__DIR__, 2) . '/tests/Fixtures/cmdi/lexer-cases.php' as $key => [$payload]) {
    echo "parse\t{$key}\t" . base64_encode($payload) . "\n";
}
