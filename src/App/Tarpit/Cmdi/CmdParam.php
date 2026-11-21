<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use Funnypot\Core\RequestContext;

/**
 * Finds the command a webshell would run: the first cmd-family parameter, from the query string
 * first and then a form-encoded body. It also says where the value came from, because only a value
 * from a non-GET body may ever be echoed back (a GET URL can be handed to someone else to open).
 */
final class CmdParam
{
    public const NAMES = ['cmd', 'command', 'exec', 'shell_exec', 'passthru'];

    /** @return array{value:string,source:string}|null */
    public static function fromContext(RequestContext $r): ?array
    {
        $v = self::find($r->query);
        if ($v !== false) {
            return $v === null ? null : ['value' => $v, 'source' => 'query'];
        }
        $type = '';
        foreach ($r->headers as $name => $value) {
            if (strcasecmp((string) $name, 'Content-Type') === 0) {
                $type = (string) $value;
            }
        }
        if ($r->rawBody !== null && $r->rawBody !== '' && stripos($type, 'application/x-www-form-urlencoded') !== false) {
            $v = self::find($r->rawBody);
            if ($v !== false) {
                return $v === null ? null : ['value' => $v, 'source' => 'body'];
            }
        }

        return null;
    }

    /** false: no cmd-family name; null: present but not a plain string; else the decoded value. */
    private static function find(string $raw): string|false|null
    {
        if ($raw === '') {
            return false;
        }
        parse_str($raw, $vars);
        foreach (self::NAMES as $n) {
            if (array_key_exists($n, $vars)) {
                return is_string($vars[$n]) ? $vars[$n] : null;
            }
        }

        return false;
    }
}
