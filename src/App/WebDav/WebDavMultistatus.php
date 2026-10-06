<?php

declare(strict_types=1);

namespace Funnypot\App\WebDav;

/**
 * FP-0200 piece 1: a PURE RFC-4918 `D:multistatus` XML builder for PROPFIND responses. Given a list of
 * resource descriptors it emits a well-formed 207 Multi-Status body a native WebDAV client (Finder,
 * Windows WebClient, Cyberduck) and scanners parse. All text (href, displayname) is XML-escaped
 * (ENT_XML1) so a captured/attacker-influenced filename can never break the document or inject markup —
 * the one place WebDAV output touches non-canned bytes.
 *
 * Pure: no I/O, no state. The handler assembles descriptors from the FakeFilesystem (reads) + the
 * WriteCaptureStore (dropped files) and calls build().
 */
final class WebDavMultistatus
{
    /**
     * @param list<array{href:string,collection:bool,size:int,contentType:string,mtime:int,displayname:string}> $resources
     */
    public static function build(array $resources): string
    {
        $out = '<?xml version="1.0" encoding="utf-8"?>' . "\n" . '<D:multistatus xmlns:D="DAV:">' . "\n";
        foreach ($resources as $r) {
            $out .= self::response($r);
        }
        $out .= '</D:multistatus>' . "\n";

        return $out;
    }

    /**
     * @param array{href:string,collection:bool,size:int,contentType:string,mtime:int,displayname:string} $r
     */
    private static function response(array $r): string
    {
        $href = self::xml($r['href']);
        $name = self::xml($r['displayname']);
        $mtime = gmdate('D, d M Y H:i:s', max(0, $r['mtime'])) . ' GMT';

        if ($r['collection']) {
            $prop = '<D:resourcetype><D:collection/></D:resourcetype>'
                . '<D:displayname>' . $name . '</D:displayname>'
                . '<D:getlastmodified>' . $mtime . '</D:getlastmodified>';
        } else {
            $prop = '<D:resourcetype/>'
                . '<D:getcontentlength>' . max(0, $r['size']) . '</D:getcontentlength>'
                . '<D:getcontenttype>' . self::xml($r['contentType']) . '</D:getcontenttype>'
                . '<D:getlastmodified>' . $mtime . '</D:getlastmodified>'
                . '<D:displayname>' . $name . '</D:displayname>';
        }

        return '  <D:response>' . "\n"
            . '    <D:href>' . $href . '</D:href>' . "\n"
            . '    <D:propstat>' . "\n"
            . '      <D:prop>' . $prop . '</D:prop>' . "\n"
            . '      <D:status>HTTP/1.1 200 OK</D:status>' . "\n"
            . '    </D:propstat>' . "\n"
            . '  </D:response>' . "\n";
    }

    private static function xml(string $s): string
    {
        return htmlspecialchars($s, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
