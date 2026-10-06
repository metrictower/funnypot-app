<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\WebDav;

use Funnypot\App\WebDav\WebDavMultistatus;
use PHPUnit\Framework\TestCase;

/**
 * FP-0200 piece 1: the RFC-4918 multistatus XML builder. The body must be well-formed XML with the DAV:
 * namespace, a response per resource, collection vs file resourcetype, and XML-escaped hrefs/names.
 */
final class WebDavMultistatusTest extends TestCase
{
    /** @return list<array{href:string,collection:bool,size:int,contentType:string,mtime:int,displayname:string}> */
    private function sample(): array
    {
        return [
            ['href' => '/webdav/', 'collection' => true, 'size' => 0, 'contentType' => '', 'mtime' => 1_700_000_000, 'displayname' => 'webdav'],
            ['href' => '/webdav/notes.txt', 'collection' => false, 'size' => 42, 'contentType' => 'text/plain', 'mtime' => 1_700_000_500, 'displayname' => 'notes.txt'],
        ];
    }

    public function test_body_is_well_formed_dav_multistatus_xml(): void
    {
        $xml = WebDavMultistatus::build($this->sample());
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($xml);
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc, 'multistatus must be well-formed XML');
        $doc->registerXPathNamespace('D', 'DAV:');
        self::assertCount(2, $doc->xpath('//D:response'), 'one response per resource');
    }

    public function test_collection_and_file_resourcetypes(): void
    {
        $xml = WebDavMultistatus::build($this->sample());
        // the collection carries <D:collection/>; the file carries a length + content type.
        self::assertStringContainsString('<D:resourcetype><D:collection/></D:resourcetype>', $xml);
        self::assertStringContainsString('<D:getcontentlength>42</D:getcontentlength>', $xml);
        self::assertStringContainsString('<D:getcontenttype>text/plain</D:getcontenttype>', $xml);
        self::assertStringContainsString('HTTP/1.1 200 OK', $xml);
    }

    public function test_filename_is_xml_escaped_no_injection(): void
    {
        $evil = [
            ['href' => '/webdav/' . rawurlencode('a&b<c>.txt'), 'collection' => false, 'size' => 1,
             'contentType' => 'text/plain', 'mtime' => 0, 'displayname' => 'a&b<c>"x".txt'],
        ];
        $xml = WebDavMultistatus::build($evil);
        self::assertStringNotContainsString('<c>', $xml, 'a raw < from a filename must be escaped');
        self::assertStringContainsString('&lt;c&gt;', $xml);
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($xml);
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc, 'an attacker-influenced displayname must not break the XML');
    }

    public function test_empty_list_is_still_valid_multistatus(): void
    {
        $xml = WebDavMultistatus::build([]);
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($xml);
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc);
    }
}
