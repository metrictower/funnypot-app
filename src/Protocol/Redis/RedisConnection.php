<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

use Funnypot\Protocol\RespEncoder;
use Funnypot\Protocol\RespParser;
use Funnypot\Protocol\RespProtocolException;
use Funnypot\Protocol\RespReply;

/**
 * One Redis connection's whole processing pipeline with NO bind: it owns the bounded inbound buffer,
 * the parser, session and engine, and the single application output queue ({@see $outbuf}) — the
 * server holds no second response buffer. This is where every output bound lives:
 *
 * - at most 16 commands run per pump tick;
 * - a complete frame is executed only while 32 KiB of the 128 KiB queue is still free for its reply,
 *   otherwise the frame is left in the input buffer for a later tick (the server disables reads until
 *   the queue drains);
 * - a reply whose measured encoded length would exceed 32 KiB is never materialised — it becomes one
 *   fixed bounded error and a close-after-flush, never a partial RESP frame.
 *
 * A malformed frame yields the exact Redis wire error and (for a multibulk violation) a close; a
 * fault in one connection never escapes to the server loop.
 */
final class RedisConnection
{
    private const INBUF_CAP = 131072; // 128 KiB of unprocessed pipelined input

    /** The ONE application output queue. The server does partial writes straight from this. */
    public string $outbuf = '';

    private string $inbuf = '';
    private RespParser $parser;
    private RedisSession $session;
    private RedisCommandEngine $engine;
    private RespEncoder $encoder;

    private bool $closeAfterFlush = false;

    public function __construct(RedisConfig $config, int $clientId = 1, string $peerIp = '')
    {
        $this->parser = new RespParser(RedisConfig::MAX_FRAME, RedisConfig::MAX_ARGV);
        $this->session = new RedisSession($config, $clientId);
        $this->session->peerIp = $peerIp;
        $this->engine = new RedisCommandEngine($config);
        $this->encoder = new RespEncoder();
    }

    public function session(): RedisSession
    {
        return $this->session;
    }

    /** Append inbound bytes. An input buffer that overflows means a client flooding faster than it
     *  reads its replies — drop it after flush rather than buffer without bound. */
    public function feed(string $bytes): void
    {
        $this->inbuf .= $bytes;
        if (strlen($this->inbuf) > self::INBUF_CAP) {
            $this->inbuf = '';
            $this->closeAfterFlush = true;
        }
    }

    /** True while the output queue has room reserved for one more full reply. */
    public function canAcceptReply(): bool
    {
        return strlen($this->outbuf) + RedisConfig::MAX_REPLY_BYTES <= RedisConfig::OUTPUT_HIGH_WATER;
    }

    public function outputPending(): bool
    {
        return $this->outbuf !== '';
    }

    /** Close once everything queued has been flushed (QUIT, protocol error, or a bound trip). */
    public function wantsClose(): bool
    {
        return $this->closeAfterFlush || $this->session->close;
    }

    /**
     * Process complete frames from the input buffer: at most 16 per call, and only while the output
     * queue can reserve a full reply. Leaves later frames buffered when the queue is near its
     * high-water mark; the server resumes the pump after the queue drains below the low-water mark.
     * Safe to drive directly with raw bytes in tests.
     */
    public function pump(): void
    {
        for ($i = 0; $i < RedisConfig::MAX_COMMANDS_PER_TICK; $i++) {
            if ($this->closeAfterFlush || $this->session->close) {
                return;
            }
            if ($this->session->commands >= RedisConfig::MAX_COMMANDS) {
                $this->closeAfterFlush = true; // per-connection command cap reached

                return;
            }
            if (!$this->canAcceptReply()) {
                return; // backpressure: leave the next frame in the input buffer for a later tick
            }

            try {
                $cmd = $this->parser->parse($this->inbuf);
            } catch (RespProtocolException $e) {
                $this->outbuf .= $this->encoder->encode(RespReply::error($e->wireError()), $this->session->respVersion);
                if ($e->closeAfter()) {
                    $this->closeAfterFlush = true;
                }

                return;
            }
            if ($cmd === null) {
                return; // incomplete frame — wait for more bytes
            }
            if ($cmd->isEmpty()) {
                continue; // *0 / blank line — Redis ignores it, nothing to reply
            }

            $reply = $this->engine->execute($cmd, $this->session);
            $len = $this->encoder->encodedLength($reply, $this->session->respVersion, RedisConfig::MAX_REPLY_BYTES);
            if ($len > RedisConfig::MAX_REPLY_BYTES) {
                // Never materialise the oversized reply, not even a prefix.
                $this->outbuf .= $this->encoder->encode(
                    RespReply::error('ERR response exceeds configured limit'),
                    $this->session->respVersion
                );
                $this->closeAfterFlush = true;

                return;
            }
            $this->outbuf .= $this->encoder->encode($reply, $this->session->respVersion);
        }
    }

    /**
     * Take and clear the safe telemetry events produced since the last drain.
     *
     * @return list<array<string,mixed>>
     */
    public function drainEvents(): array
    {
        $events = $this->session->events;
        $this->session->events = [];

        return $events;
    }
}
