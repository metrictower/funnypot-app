<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Tracks the state of an active SIP dialog and its associated RTP media stream.
 */
final class SipSession
{
    public const STATE_IDLE = 'idle';
    public const STATE_TRYING = 'trying';
    public const STATE_RINGING = 'ringing';
    public const STATE_CONNECTED = 'connected';
    public const STATE_STREAMING = 'streaming';
    public const STATE_ENDED = 'ended';

    public string $state = self::STATE_IDLE;

    public string $callId = '';
    public string $fromTag = '';
    public string $toTag = '';
    public int $cseqNumber = 1;
    public string $cseqMethod = 'INVITE';

    public string $peerIp = '';
    public int $peerPort = 5060;
    public string $transport = 'udp'; // 'udp' | 'tcp'

    /** @var resource|null TCP stream handle (if transport is TCP) */
    public $tcpSocket = null;
    public string $tcpInbuf = '';

    public string $dialedNumber = 'unknown';
    public string $persona = 'lenny';

    // RTP Media destination and streaming parameters
    public string $remoteRtpIp = '';
    public int $remoteRtpPort = 0;
    public int $rtpSeq = 0;
    public int $rtpTimestamp = 0;
    public int $rtpSsrc = 0;
    public int $rtpPacketsSent = 0;

    // FP-0247 anti-spoof: latched true once the session reaches STREAMING via a validated ACK (the
    // To-tag return-routability check in handleAck). A session created by a spoofed INVITE and then
    // reaped by setup-stall eviction, or torn down by a spoofed BYE, never sets this — so its
    // call_end event must not be reported (a single spoofed UDP datagram could otherwise blame an
    // innocent source). isStreaming() only reflects the CURRENT state; this remembers that the call
    // ever passed the handshake, which is what endSession needs after the state has moved on.
    public bool $wasStreaming = false;

    public float $startTime = 0.0;
    // A ringing call is answered here (0 = no answer pending). The 200 OK is pre-built and held so
    // the answer time can vary call-to-call without the select loop ever blocking on a sleep; the
    // caller's phone renders the repeating ring cadence from our 180 Ringing while it waits.
    public float $answerAt = 0.0;
    public string $pendingOk = '';
    public float $lastRtpSendTime = 0.0;
    // Last time the CALLER sent us anything (RTP or signaling). Drives hangup/idle detection —
    // distinct from lastRtpSendTime, which tracks our own outbound stream clock.
    public float $lastInboundTime = 0.0;

    // Soundboard pacing state
    public int $personaClipIndex = 0;
    public int $personaClipOffset = 0;
    public int $personaPauseRemaining = 0;

    // Call recording buffers: our outbound persona stream, and the caller's inbound stream
    // (the intel). Written as the two channels of a stereo recording.
    public string $recordedUlaw = '';
    public string $recordedInbound = '';
    public string $recordingUrl = '';

    // Attacker attribution captured at call setup: the raw User-Agent and our tool guess.
    public string $userAgent = '';
    public string $tool = '';

    // DTMF capture (RFC 4733 telephone-event). $dtmfPt is the payload type the caller offered in
    // its SDP (default 101); $dtmfDigits accumulates each pressed key. A single key-press spans many
    // RTP packets sharing one timestamp — $lastDtmfTs dedups them so each digit is recorded once.
    public ?int $dtmfPt = null;
    public string $dtmfDigits = '';
    public int $lastDtmfTs = -1;

    public function __construct(string $callId, string $peerIp, int $peerPort, string $transport = 'udp')
    {
        $this->callId = $callId;
        $this->peerIp = $peerIp;
        $this->peerPort = $peerPort;
        $this->transport = $transport;

        // Strictly pin the RTP destination IP to the incoming signaling source IP (Anti-Reflection Invariant B1)
        $this->remoteRtpIp = $peerIp;

        $this->toTag = SipMessage::asteriskTag();
        $this->rtpSeq = random_int(1000, 50000);
        $this->rtpTimestamp = random_int(10000, 500000);
        $this->rtpSsrc = random_int(100000, 9999999);
        $this->startTime = microtime(true);
    }

    public function isStreaming(): bool
    {
        // Only STREAMING (reached via a validated ACK) streams RTP. STATE_CONNECTED (set on INVITE,
        // before any ACK) must NOT stream — otherwise a single spoofed INVITE would blast RTP at a
        // spoofed victim, turning the honeypot into a reflection/amplification weapon.
        return $this->state === self::STATE_STREAMING && $this->remoteRtpPort > 0;
    }

    public function getDuration(): float
    {
        return max(0.0, microtime(true) - $this->startTime);
    }
}
