<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Smtp;

use Funnypot\Protocol\ProtocolEmulator;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Smtp\SmtpSession;
use PHPUnit\Framework\TestCase;

final class SmtpSessionTest extends TestCase
{
    private function sess(): SmtpSession
    {
        return new SmtpSession(1234, 'mail.example.com');
    }

    public function testBannerIsEsmtpGreeting(): void
    {
        self::assertSame("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", $this->sess()->banner());
    }

    public function testEhloIsMultilineAndOmitsStarttls(): void
    {
        $s = $this->sess();
        $reply = $s->feed('EHLO scanner.example');
        $lines = array_values(array_filter(explode("\r\n", $reply)));

        // Every line but the last is a 250- continuation; the last is 250<space>.
        self::assertStringStartsWith('250-mail.example.com', $lines[0]);
        $last = $lines[count($lines) - 1];
        self::assertStringStartsWith('250 ', $last);
        foreach (array_slice($lines, 0, -1) as $l) {
            self::assertStringStartsWith('250-', $l);
        }
        // STARTTLS must NOT be advertised (we keep the attacker in plaintext to harvest creds).
        self::assertStringNotContainsStringIgnoringCase('STARTTLS', $reply);
        self::assertStringContainsString('AUTH PLAIN LOGIN', $reply);
    }

    public function testCommandOrderingErrors(): void
    {
        $s = $this->sess();
        self::assertStringStartsWith('503', $s->feed('MAIL FROM:<a@b.c>')); // before HELO
        $s->feed('EHLO x');
        self::assertStringStartsWith('503', $s->feed('RCPT TO:<a@b.c>'));    // before MAIL
        $s->feed('MAIL FROM:<a@b.c>');
        self::assertStringStartsWith('503', $s->feed('DATA'));               // before RCPT
    }

    /** The regression this ticket fixes: DATA body lines must NOT be answered as commands. */
    public function testDataBodyLinesAreCollectedNotRejected(): void
    {
        $s = $this->sess();
        $s->feed('EHLO scanner');
        self::assertStringStartsWith('250', $s->feed('MAIL FROM:<spam@evil.test>'));
        self::assertStringStartsWith('250', $s->feed('RCPT TO:<victim@example.com>'));
        self::assertStringStartsWith('354', $s->feed('DATA'));

        // Body lines — a stateless matcher answered each of these "502 command not recognized".
        self::assertSame('', $s->feed('Subject: cheap pills'));
        self::assertSame('', $s->feed('MAIL FROM is a header-looking line, still body'));
        self::assertSame('', $s->feed(''));
        self::assertSame('', $s->feed('body line with QUIT in it'));

        // The lone dot ends the message with a queued-id acceptance.
        $end = $s->feed('.');
        self::assertStringStartsWith('250 2.0.0 Ok: queued as ', $end);

        $msgs = $s->messages();
        self::assertCount(1, $msgs);
        self::assertSame('spam@evil.test', $msgs[0]['from']);
        self::assertSame(['victim@example.com'], $msgs[0]['rcpt']);
        self::assertStringContainsString('Subject: cheap pills', $msgs[0]['body']);
        self::assertStringContainsString('QUIT', $msgs[0]['body']); // QUIT-in-body stayed body
    }

    public function testDotStuffingTransparency(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        $s->feed('MAIL FROM:<a@b.c>');
        $s->feed('RCPT TO:<d@e.f>');
        $s->feed('DATA');
        $s->feed('..leading dot line'); // one leading dot is stripped
        $s->feed('.');
        self::assertStringContainsString(".leading dot line", $s->messages()[0]['body']);
    }

    public function testAuthLoginHarvestAndReject(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        self::assertStringStartsWith('334 ', $s->feed('AUTH LOGIN'));
        self::assertStringStartsWith('334 ', $s->feed(base64_encode('bob@corp')));
        $reject = $s->feed(base64_encode('hunter2'));
        // Never authenticates — always 535.
        self::assertStringStartsWith('535', $reject);

        $attempts = $s->authAttempts();
        self::assertCount(1, $attempts);
        self::assertSame('bob@corp', $attempts[0]['user']);
        self::assertSame('hunter2', $attempts[0]['pass']);
        self::assertSame('LOGIN', $attempts[0]['mechanism']);
    }

    public function testAuthPlainInlineHarvest(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        $token = base64_encode("\0alice\0s3cret");
        $reject = $s->feed('AUTH PLAIN ' . $token);
        self::assertStringStartsWith('535', $reject);

        $attempts = $s->authAttempts();
        self::assertCount(1, $attempts);
        self::assertSame('alice', $attempts[0]['user']);
        self::assertSame('s3cret', $attempts[0]['pass']);
    }

    public function testIntelEventsAreDrained(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        $s->feed('AUTH PLAIN ' . base64_encode("\0u\0p"));
        $intel = $s->drainIntel();
        self::assertNotEmpty($intel);
        self::assertStringContainsString('smtp-auth PLAIN user=u pass=p', $intel[0]);
    }

    public function testQuitClosesAndUnknownIs502(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        self::assertStringStartsWith('502', $s->feed('WHATISTHIS'));
        self::assertFalse($s->closed());
        self::assertStringStartsWith('221', $s->feed('QUIT'));
        self::assertTrue($s->closed());
    }

    public function testRsetClearsTransaction(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        $s->feed('MAIL FROM:<a@b.c>');
        self::assertStringStartsWith('250', $s->feed('RSET'));
        // After RSET, RCPT must fail (no MAIL in effect).
        self::assertStringStartsWith('503', $s->feed('RCPT TO:<d@e.f>'));
    }

    public function testMessageUnderAdvertisedSizeIsAccepted(): void
    {
        // EHLO advertises SIZE 10240000; a ~2 MB message is well under it and must NOT be 552'd.
        $s = $this->sess();
        self::assertStringContainsString('SIZE 10240000', $s->feed('EHLO x'));
        $s->feed('MAIL FROM:<a@b.c>');
        $s->feed('RCPT TO:<d@e.f>');
        $s->feed('DATA');
        $chunk = str_repeat('A', 4096);
        for ($i = 0; $i < 500; $i++) { // ~2 MB, under the advertised 10 MB
            self::assertSame('', $s->feed($chunk));
        }
        self::assertStringStartsWith('250 2.0.0 Ok: queued as ', $s->feed('.'));
    }

    public function testOversizeMessageIsRejectedAndClosed(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        $s->feed('MAIL FROM:<a@b.c>');
        $s->feed('RCPT TO:<d@e.f>');
        $s->feed('DATA');
        $chunk = str_repeat('A', 8192);
        $hit552 = false;
        for ($i = 0; $i < 1400; $i++) { // ~11 MB > 10240000 ceiling
            $r = $s->feed($chunk);
            if ($r !== '') {
                self::assertStringStartsWith('552', $r); // refused mid-stream, not after a dot
                $hit552 = true;
                break;
            }
        }
        self::assertTrue($hit552, 'expected a 552 once the body crossed the advertised SIZE');
        self::assertTrue($s->closed());           // connection dropped (bounds a no-dot flood)
        self::assertCount(0, $s->messages());      // oversize message is not retained
    }

    /** End-to-end through the emulator: engine:smtp dispatch, byte stream in, intel via onRequest. */
    public function testEmulatorDispatchAndIntelForwarding(): void
    {
        $emulator = new ProtocolEmulator(['framing' => 'line', 'engine' => 'smtp'], null, 42);
        $s = new ProtocolSession(42);

        self::assertStringStartsWith('220 ', $emulator->banner($s));

        $log = [];
        $onRequest = function (string $cmd, string $resp) use (&$log): void {
            $log[] = $cmd;
        };

        // A scanner's AUTH probe arrives as one TCP chunk of CRLF-framed lines.
        $wire = "EHLO scanner\r\nAUTH LOGIN\r\n" . base64_encode('root') . "\r\n" . base64_encode('toor') . "\r\n";
        $out = $emulator->feed($wire, $s, $onRequest);

        self::assertStringContainsString('535', $out); // auth rejected
        // The decoded credential intel was forwarded through the logging seam.
        $joined = implode("\n", $log);
        self::assertStringContainsString('smtp-auth LOGIN user=root pass=toor', $joined);

        // QUIT closes the connection via the engine.
        $emulator->feed("QUIT\r\n", $s, $onRequest);
        self::assertTrue($s->close);
    }

    public function testQueueIdVariesPerConnectionNonce(): void
    {
        $mk = function (string $nonce): string {
            $s = new SmtpSession(777, 'h', $nonce);
            $s->feed('EHLO x');
            $s->feed('MAIL FROM:<a@b.c>');
            $s->feed('RCPT TO:<d@e.f>');
            $s->feed('DATA');
            return $s->feed('.');
        };
        // Same seed+nonce -> deterministic (unit-test reproducibility).
        self::assertSame($mk('n1'), $mk('n1'));
        // Different per-connection nonce (what the emulator injects) -> different queue id, so two
        // connections from one source IP (identical seed) never reuse an id — no real MTA does.
        self::assertNotSame($mk('n1'), $mk('n2'));
    }

    public function testNestedMailIsRejected(): void
    {
        $s = $this->sess();
        $s->feed('EHLO x');
        self::assertStringStartsWith('250', $s->feed('MAIL FROM:<a@b.c>'));
        self::assertStringStartsWith('503', $s->feed('MAIL FROM:<x@y.z>')); // nested MAIL
    }

    public function testAuthRequiresGreetingAndNoTransaction(): void
    {
        // AUTH before HELO/EHLO -> 503 (Postfix only offers AUTH after EHLO).
        $s1 = $this->sess();
        self::assertStringStartsWith('503', $s1->feed('AUTH LOGIN'));

        // AUTH mid-transaction -> 503.
        $s2 = $this->sess();
        $s2->feed('EHLO x');
        $s2->feed('MAIL FROM:<a@b.c>');
        self::assertStringStartsWith('503', $s2->feed('AUTH LOGIN'));

        // AUTH after EHLO, no transaction -> proceeds to the 334 challenge.
        $s3 = $this->sess();
        $s3->feed('EHLO x');
        self::assertStringStartsWith('334', $s3->feed('AUTH LOGIN'));
    }

    public function testStarttlsIsAnUnknownVerbNot454(): void
    {
        // STARTTLS is not advertised; answering it as a known-but-unavailable verb (454) would be a
        // presence tell. It must read as an unrecognized command.
        $s = $this->sess();
        $s->feed('EHLO x');
        $reply = $s->feed('STARTTLS');
        self::assertStringStartsWith('502', $reply);
        self::assertStringNotContainsString('454', $reply);
    }

    /** L4: a DATA body longer than the command cap must still be accepted (not force-closed). */
    public function testLargeBodyIsNotTruncatedByRequestCap(): void
    {
        $emulator = new ProtocolEmulator(['framing' => 'line', 'engine' => 'smtp'], null, 7);
        $s = new ProtocolSession(7);
        $emulator->banner($s);
        $emulator->feed("EHLO scanner\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nDATA\r\n", $s);

        // 900 body lines — well past the 500 command cap. Feed line by line.
        $wire = '';
        for ($i = 0; $i < 900; $i++) {
            $wire .= 'spam body line ' . $i . "\r\n";
        }
        $out = $emulator->feed($wire, $s);
        self::assertSame('', $out);             // server stays silent during the body
        self::assertFalse($s->close);            // NOT force-closed mid-body

        $end = $emulator->feed(".\r\n", $s);
        self::assertStringStartsWith('250 2.0.0 Ok: queued as ', $end); // full message accepted
    }
}
