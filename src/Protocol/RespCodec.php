<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Redis RESP framing adapter for the compiled-template (catalog / malformed-style) path. A client
 * request is either an inline command (`PING\r\n`) or an array of bulk strings
 * (`*2\r\n$4\r\nAUTH\r\n$3\r\nfoo\r\n`); either way `extract()` yields the command with its
 * arguments joined by a space, so a rule matches on "AUTH foo" / "CONFIG GET dir".
 *
 * The binary-safe framing lives in {@see RespParser}; this class delegates to it and joins the argv
 * at the string boundary the rule matcher needs. The dedicated interactive Redis engine consumes
 * RespCommand from the parser directly and never joins argv. A malformed frame is rendered inert
 * (one empty request, offending line consumed) to keep the template path robust.
 *
 * `wrap()` frames the author's semantic reply:
 *   "+PONG\r\n" (verbatim) · {simple: s} → +s · {error: s} → -s
 *   {bulk: s} → $len\r\n s \r\n · {bulk_array: [a,b]} → *N\r\n $..\r\n a \r\n ...
 */
final class RespCodec implements Codec
{
    private RespParser $parser;

    public function __construct()
    {
        // A generous argv budget for the legacy adapter — the interactive engine applies the
        // tight per-command caps; here the only job is to frame catalog-rule matches robustly.
        $this->parser = new RespParser(RespParser::DEFAULT_MAX_FRAME, 1024);
    }

    public function extract(string &$buffer): array
    {
        $out = [];
        while ($buffer !== '') {
            try {
                $cmd = $this->parser->parse($buffer);
            } catch (RespProtocolException $e) {
                if (!$this->consumeBadLine($buffer)) {
                    break;
                }
                $out[] = ''; // inert: matches no rule, drops to the default error
                continue;
            }
            if ($cmd === null) {
                break; // incomplete frame — leave $buffer untouched, wait for more bytes
            }
            if ($cmd->isEmpty()) {
                continue; // *0 / blank inline line: already consumed, nothing to match
            }
            $out[] = implode(' ', $cmd->args());
        }

        return $out;
    }

    /** Consume the offending header/inline line after a framing error; false if no terminator yet. */
    private function consumeBadLine(string &$buffer): bool
    {
        $nl = strpos($buffer, "\n");
        if ($nl === false) {
            return false;
        }
        $buffer = substr($buffer, $nl + 1);

        return true;
    }

    /** @param string|array<string,mixed> $send */
    public function wrap($send): string
    {
        if (!is_array($send)) {
            return (string) $send;
        }
        if (isset($send['simple'])) {
            return '+' . (string) $send['simple'] . "\r\n";
        }
        if (isset($send['error'])) {
            return '-' . (string) $send['error'] . "\r\n";
        }
        if (isset($send['bulk'])) {
            $s = (string) $send['bulk'];

            return '$' . strlen($s) . "\r\n" . $s . "\r\n";
        }
        if (isset($send['bulk_array'])) {
            $items = (array) $send['bulk_array'];
            $out = '*' . count($items) . "\r\n";
            foreach ($items as $item) {
                $s = (string) $item;
                $out .= '$' . strlen($s) . "\r\n" . $s . "\r\n";
            }

            return $out;
        }

        return (string) ($send['raw'] ?? '');
    }
}
