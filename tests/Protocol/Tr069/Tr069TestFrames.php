<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Tr069;

/**
 * Byte builders for the TR-069 / CWMP tests: an HTTP request framer and small SOAP envelope helpers
 * (SetNTPServers, SetParameterValues, Download, GetParameterValues, Inform). Just enough structure to
 * exercise every field the honeypot's parsers read.
 */
trait Tr069TestFrames
{
    /**
     * @param array<string,string> $headers
     */
    private static function request(string $method, string $path, array $headers = [], string $body = ''): string
    {
        $lines = ["{$method} {$path} HTTP/1.1", 'Host: 10.0.0.5:7547'];
        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }
        if ($body !== '') {
            $lines[] = 'Content-Length: ' . strlen($body);
        }

        return implode("\r\n", $lines) . "\r\n\r\n" . $body;
    }

    /** A TR-064 SetNTPServers POST carrying the given NewNTPServer1 value. */
    private static function setNtpServersRequest(string $ntpServer1, array $headers = []): string
    {
        $body = '<?xml version="1.0"?>'
            . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            . '<SOAP-ENV:Body>'
            . '<u:SetNTPServers xmlns:u="urn:dslforum-org:service:Time:1">'
            . '<NewNTPServer1>' . $ntpServer1 . '</NewNTPServer1>'
            . '<NewNTPServer2></NewNTPServer2>'
            . '</u:SetNTPServers>'
            . '</SOAP-ENV:Body></SOAP-ENV:Envelope>';

        $headers += ['SOAPAction' => '"urn:dslforum-org:service:Time:1#SetNTPServers"', 'Content-Type' => 'text/xml'];

        return self::request('POST', '/UD/act?1', $headers, $body);
    }

    /** A TR-069 SetParameterValues POST with one Name/Value struct. */
    private static function setParameterValuesRequest(string $name, string $value, array $headers = []): string
    {
        $body = '<?xml version="1.0"?>'
            . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'
            . '<SOAP-ENV:Body>'
            . '<cwmp:SetParameterValues>'
            . '<ParameterList>'
            . '<ParameterValueStruct><Name>' . $name . '</Name><Value>' . $value . '</Value></ParameterValueStruct>'
            . '</ParameterList>'
            . '</cwmp:SetParameterValues>'
            . '</SOAP-ENV:Body></SOAP-ENV:Envelope>';

        $headers += ['Content-Type' => 'text/xml'];

        return self::request('POST', '/', $headers, $body);
    }

    /** A TR-069 Download POST. */
    private static function downloadRequest(string $url, array $headers = []): string
    {
        $body = '<?xml version="1.0"?>'
            . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'
            . '<SOAP-ENV:Body>'
            . '<cwmp:Download>'
            . '<CommandKey>k</CommandKey><FileType>1 Firmware Upgrade Image</FileType>'
            . '<URL>' . $url . '</URL><Username>u</Username><Password>p</Password>'
            . '</cwmp:Download>'
            . '</SOAP-ENV:Body></SOAP-ENV:Envelope>';

        $headers += ['Content-Type' => 'text/xml'];

        return self::request('POST', '/cwmp', $headers, $body);
    }

    /** A TR-069 GetParameterValues recon POST. */
    private static function getParameterValuesRequest(array $headers = []): string
    {
        $body = '<?xml version="1.0"?>'
            . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'
            . '<SOAP-ENV:Body>'
            . '<cwmp:GetParameterValues><ParameterNames>'
            . '<string>InternetGatewayDevice.DeviceInfo.SerialNumber</string>'
            . '</ParameterNames></cwmp:GetParameterValues>'
            . '</SOAP-ENV:Body></SOAP-ENV:Envelope>';

        $headers += ['Content-Type' => 'text/xml'];

        return self::request('POST', '/', $headers, $body);
    }

    /** A TR-069 Inform POST (a scanner posing as a CPE). */
    private static function informRequest(string $oui, string $productClass, string $serial, array $headers = []): string
    {
        $body = '<?xml version="1.0"?>'
            . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'
            . '<SOAP-ENV:Body>'
            . '<cwmp:Inform>'
            . '<DeviceId>'
            . '<Manufacturer>Acme</Manufacturer>'
            . '<OUI>' . $oui . '</OUI>'
            . '<ProductClass>' . $productClass . '</ProductClass>'
            . '<SerialNumber>' . $serial . '</SerialNumber>'
            . '</DeviceId>'
            . '<Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode></EventStruct>'
            . '<EventStruct><EventCode>1 BOOT</EventCode></EventStruct></Event>'
            . '</cwmp:Inform>'
            . '</SOAP-ENV:Body></SOAP-ENV:Envelope>';

        $headers += ['Content-Type' => 'text/xml'];

        return self::request('POST', '/', $headers, $body);
    }
}
