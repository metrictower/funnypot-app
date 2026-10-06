<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rsync;

/**
 * Per-connection rsync daemon state machine (FP-0164, MVP). Line-framed text phase: greet with the
 * version+digest banner, read the client's version reply, then serve `#list` module enumeration or a
 * module-access request (`@RSYNCD: OK` + capture the client's argument list). Covers `rsync <host>::`
 * and `nmap --script rsync-list-modules`.
 *
 * INERT / zero-disk: module names/descriptions come from {@see RsyncConfig} (in-memory persona), nothing
 * is read from the host filesystem. The binary file-list/transfer is the deferred FP-0608 follow-up — the
 * MVP accepts the module, captures the args (intel), and closes. Testable without a socket via {@see receive()}.
 */
final class RsyncSession
{
    private const STATE_AWAIT_VERSION = 0;
    private const STATE_AWAIT_COMMAND = 1;
    private const STATE_COLLECT_ARGS = 2;

    private const INBUF_CAP = 16384;   // the text phase is tiny; a flood past this is hostile
    private const MAX_LINE = 1024;     // a single rsync protocol line never legitimately exceeds this
    private const MAX_ARG_LINES = 64;  // bound the captured argument list

    /** @var callable(array<string,mixed>):void */
    private $logger;

    private string $inbuf = '';
    private int $state = self::STATE_AWAIT_VERSION;
    private string $clientVersion = '';
    private string $accessedModule = '';
    /** @var list<string> */
    private array $args = [];
    public bool $close = false;

    /** @param callable(array<string,mixed>):void $logger */
    public function __construct(
        private RsyncConfig $config,
        callable $logger,
        private string $ip = ''
    ) {
        $this->logger = $logger;
    }

    /** The greeting a real daemon sends immediately on connect (queued by the server). */
    public function greeting(): string
    {
        return $this->config->greeting();
    }

    /** Feed inbound bytes; return bytes to write back. */
    public function receive(string $bytes): string
    {
        $this->inbuf .= $bytes;
        if (\strlen($this->inbuf) > self::INBUF_CAP) {
            throw new \RuntimeException('rsync: inbound buffer exceeded cap');
        }

        $out = '';
        while (($nl = \strpos($this->inbuf, "\n")) !== false) {
            $line = \substr($this->inbuf, 0, $nl);
            $this->inbuf = \substr($this->inbuf, $nl + 1);
            if (\strlen($line) > self::MAX_LINE) {
                $out .= $this->error('protocol startup error (bad session)');
                break;
            }
            $out .= $this->onLine(\rtrim($line, "\r"));
            if ($this->close) {
                break;
            }
        }

        return $out;
    }

    private function onLine(string $line): string
    {
        switch ($this->state) {
            case self::STATE_AWAIT_VERSION:
                // Expect the client echoing "@RSYNCD: <version>". Anything else = a bad session.
                if (\strncmp($line, '@RSYNCD:', 8) !== 0) {
                    return $this->error('protocol startup error (bad session)');
                }
                $this->clientVersion = \trim(\substr($line, 8));
                $this->state = self::STATE_AWAIT_COMMAND;

                return '';

            case self::STATE_AWAIT_COMMAND:
                return $this->onCommand($line);

            case self::STATE_COLLECT_ARGS:
                return $this->onArg($line);
        }

        return '';
    }

    private function onCommand(string $line): string
    {
        if ($line === '' || $line === '#list') {
            // Module enumeration: name TAB description, then EXIT.
            $out = '';
            foreach ($this->config->modules as $name => $desc) {
                $out .= $name . "\t" . $desc . "\n";
            }
            $out .= "@RSYNCD: EXIT\n";
            $this->close = true;
            ($this->logger)([
                'event' => 'rsync_module_list',
                'ip' => $this->ip,
                'proto' => 'rsync',
                'path' => '#list',
                'reportable' => true,
            ]);

            return $out;
        }

        // Module access request.
        $module = \strtolower($line);
        if (!isset($this->config->modules[$module])) {
            $this->close = true;

            return $this->error("Unknown module '" . $this->sanitize($line) . "'");
        }
        $this->accessedModule = $module;
        $this->state = self::STATE_COLLECT_ARGS;

        return "@RSYNCD: OK\n";
    }

    private function onArg(string $line): string
    {
        // The client sends its rsync argument list terminated by a blank line.
        if ($line === '') {
            $this->close = true;
            ($this->logger)([
                'event' => 'rsync_module_access',
                'ip' => $this->ip,
                'proto' => 'rsync',
                'path' => $this->accessedModule,
                'command' => \implode(' ', $this->args),
                'body' => \implode("\n", $this->args),
                'reportable' => true,
            ]);

            // MVP: no file stream (binary transfer is FP-0608). Close after capturing the request.
            return "@RSYNCD: EXIT\n";
        }
        if (\count($this->args) < self::MAX_ARG_LINES) {
            $this->args[] = $this->sanitize($line);
        }

        return '';
    }

    private function error(string $msg): string
    {
        $this->close = true;

        return '@ERROR: ' . $msg . "\n";
    }

    /** Strip control bytes from captured/echoed attacker input (no reflection of raw control chars). */
    private function sanitize(string $s): string
    {
        return \preg_replace('/[\x00-\x1F\x7F]/', '', $s) ?? '';
    }
}
