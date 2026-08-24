<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT helpdesk / ITSM corpus for the deep office panel (spec §C.7) — the
 * lateral-movement intel lure. It is a VIEW over the `Org` roster: a ticket's requester and assignee are
 * real employees at the host's one domain, so a name on a ticket resolves to the same person in the HR
 * directory and everywhere else. The threaded detail carries credential-shaped bait in an internal note,
 * which the honeypot's never-authenticating login dead-ends.
 *
 * Design rules (deep-admin dashboard spec §C.7 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); every date is formatted off the one frozen clock (FrozenClock), so a
 *    static reload is byte-identical and never a tell.
 *  - COHERENT: requester/assignee are Org roster members; the assignee is drawn from the IT department so
 *    the queue reads as a real IT team. Ids map back to a corpus index (an id round-trips to its row).
 *  - SAFE: any source IP is the employee VLAN (10.0.20.x via Org), RFC1918 only. The credential-shaped
 *    bait is fabricated text, never a real secret, and authenticates against nothing.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/promotion/str_contains/arrow fns) so a fact can
 *    promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Helpdesk
{
    private const FY = '2026';

    /** First ticket index -> ticket number, so an id maps back to a corpus index. */
    private const TKT_BASE = 100001;

    /** @var int */
    private $seed;

    /** @var string host persona domain — requester/assignee emails render here (one host = one domain). */
    private $domain;

    /** @var Org */
    private $org;

    /** @var array<int,array>|null cached IT-department roster slice (assignee pool). */
    private $itStaff = null;

    private function __construct(int $seed, string $domain)
    {
        $this->seed = $seed;
        $this->domain = $domain;
        $this->org = Org::fromSeed($seed, $domain);
    }

    public static function fromSeed(int $seed, string $domain = ''): self
    {
        return new self($seed, $domain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|hd|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    /** YYYY-MM-DD for the frozen "now" minus $daysBack, from the one shared clock (no date()). */
    private function dayBack(int $daysBack): string
    {
        return FrozenClock::ymdFromDays(FrozenClock::nowDays() - $daysBack);
    }

    // --- roster views ---

    /** The IT-department roster slice used for assignees; the whole roster if no IT staff exist. */
    private function itStaff(): array
    {
        if ($this->itStaff !== null) {
            return $this->itStaff;
        }
        $roster = $this->org->people($this->org->headcount());
        $it = [];
        foreach ($roster as $p) {
            if ($p['dept'] === 'IT' || $p['dept'] === 'Support' || $p['dept'] === 'Security') {
                $it[] = $p;
            }
        }
        $this->itStaff = $it !== [] ? array_values($it) : $roster;
        return $this->itStaff;
    }

    // --- ticket corpus ---

    /** A large, seeded corpus size so paginated enumeration is effectively bottomless but deterministic. */
    public function ticketCount(): int
    {
        return $this->intIn(9000, 22000, 'tktcount');
    }

    /**
     * One page of tickets by absolute offset, so page 80 renders identically and instantly.
     *
     * @return list<array> each element is a full ticketAt() record
     */
    public function ticketPage(int $offset, int $limit): array
    {
        $total = $this->ticketCount();
        if ($offset < 0) {
            $offset = 0;
        }
        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            if ($i >= $total) {
                break;
            }
            $out[] = $this->ticketAt($i);
        }
        return $out;
    }

    /**
     * One ticket by 0-based corpus index. Requester and assignee are real Org roster members; the
     * threaded comments are deterministic and carry (on some tickets) credential-shaped bait.
     *
     * @return array{index:int,number:string,id:string,subject:string,category:string,priority:string,status:string,requester:string,requesterEmail:string,requesterDept:string,assignee:string,assigneeEmail:string,created:string,updated:string,description:string,comments:list<array{author:string,when:string,body:string,internal:bool}>,attachments:list<string>}
     */
    public function ticketAt(int $i): array
    {
        $n = $this->org->headcount();
        $requester = $this->org->people($n)[$this->h('tkt-req|' . $i) % $n];
        $itPool = $this->itStaff();
        $assignee = $itPool[$this->h('tkt-asg|' . $i) % count($itPool)];

        $category = $this->pick(
            ['Access request', 'Password reset', 'Hardware failure', 'Software install', 'Network',
             'Email', 'VPN', 'Printer', 'Onboarding', 'Offboarding', 'Mobile device', 'Security incident'],
            'tkt-cat|' . $i
        );
        $priority = $this->priorityFor($i);
        $status = $this->pick(['Open', 'In Progress', 'Pending', 'Resolved', 'Closed'], 'tkt-st|' . $i);

        $createdBack = $this->intIn(1, 540, 'tkt-cd|' . $i);
        $updatedBack = $this->intIn(0, $createdBack, 'tkt-ud|' . $i);

        $number = sprintf('HD-%s-%06d', self::FY, self::TKT_BASE + $i);
        return [
            'index' => $i,
            'number' => $number,
            'id' => strtolower($number),
            'subject' => $this->subjectFor($category, $requester, $i),
            'category' => $category,
            'priority' => $priority,
            'status' => $status,
            'requester' => $requester['name'],
            'requesterEmail' => $requester['email'],
            'requesterDept' => $requester['dept'],
            'assignee' => $assignee['name'],
            'assigneeEmail' => $assignee['email'],
            'created' => $this->dayBack($createdBack),
            'updated' => $this->dayBack($updatedBack),
            'description' => $this->descriptionFor($category, $requester, $i),
            'comments' => $this->commentsFor($category, $requester, $assignee, $i),
            'attachments' => $this->attachmentsFor($category, $number, $i),
        ];
    }

    /**
     * One ticket by its (slugified) number. A known id in range returns its exact corpus row; an
     * unknown/fuzzed slug returns a plausible seeded ticket keyed by the slug so a crawl never dead-ends
     * (a 404 inside the panel is a tell).
     */
    public function ticketByIdSlug(string $slug): array
    {
        $slug = strtolower($slug);
        $prefix = 'hd-' . strtolower(self::FY) . '-';
        if (strpos($slug, $prefix) === 0) {
            $num = substr($slug, strlen($prefix));
            if ($num !== '' && ctype_digit($num)) {
                $i = ((int) $num) - self::TKT_BASE;
                if ($i >= 0 && $i < $this->ticketCount()) {
                    return $this->ticketAt($i);
                }
            }
        }
        return $this->ticketAt($this->h('synt|' . $slug) % $this->ticketCount());
    }

    // --- ticket field builders ---

    /** P1 is rare, most tickets are P3/P4 — a budgeted severity spread, never a queue full of P1s. */
    private function priorityFor(int $i): string
    {
        $r = $this->h('tkt-pr|' . $i) % 100;
        if ($r < 4) {
            return 'P1';
        }
        if ($r < 20) {
            return 'P2';
        }
        if ($r < 60) {
            return 'P3';
        }
        return 'P4';
    }

    private function subjectFor(string $category, array $requester, int $i): string
    {
        switch ($category) {
            case 'Access request':
                return 'Access request — ' . $this->pick(['shared drive', 'finance folder', 'VPN group', 'admin console', 'HR system'], 'tkt-sa|' . $i);
            case 'Password reset':
                return 'Password reset for ' . $requester['name'];
            case 'Hardware failure':
                return $this->pick(['Laptop will not boot', 'Docking station dead', 'Monitor flickering', 'Battery not charging'], 'tkt-sh|' . $i);
            case 'Printer':
                return $this->pick(['Cannot print to floor MFP', 'Scan-to-email failing', 'Toner low warning stuck', 'Print jobs stuck in queue'], 'tkt-sp|' . $i);
            case 'VPN':
                return $this->pick(['VPN disconnects every few minutes', 'Cannot reach internal apps over VPN', 'MFA prompt not arriving'], 'tkt-sv|' . $i);
            case 'Email':
                return $this->pick(['Mailbox full', 'Not receiving external mail', 'Suspicious email received', 'Calendar not syncing'], 'tkt-se|' . $i);
            case 'Security incident':
                return $this->pick(['Possible phishing click', 'Lost device report', 'Unexpected MFA prompts', 'Antivirus alert on endpoint'], 'tkt-ss|' . $i);
            default:
                return $category . ' request for ' . $requester['name'];
        }
    }

    private function descriptionFor(string $category, array $requester, int $i): string
    {
        return $requester['name'] . ' (' . $requester['dept'] . ') reports: '
            . $this->pick(
                [
                    'Issue started this morning and is blocking their work.',
                    'Intermittent since the last update; happens a few times a day.',
                    'Needs this resolved before an upcoming client meeting.',
                    'Reproduces on both office and home network.',
                    'Colleague on the same team is not affected.',
                ],
                'tkt-desc|' . $i
            );
    }

    /**
     * A deterministic comment thread. One internal note carries credential-shaped bait on some tickets —
     * a fabricated temporary password that the never-authenticating login turns into a dead end.
     *
     * @return list<array{author:string,when:string,body:string,internal:bool}>
     */
    private function commentsFor(string $category, array $requester, array $assignee, int $i): array
    {
        $out = [];
        $count = $this->intIn(2, 6, 'tkt-cc|' . $i);
        $openBack = $this->intIn(1, 540, 'tkt-cd|' . $i);
        $plantBait = ($category === 'Password reset' || $category === 'Onboarding')
            && ($this->h('tkt-bait|' . $i) % 2 === 0);

        for ($k = 0; $k < $count; $k++) {
            $back = $openBack - (int) round($openBack * $k / max(1, $count));
            $fromRequester = ($k % 2 === 0);
            $author = $fromRequester ? $requester['name'] : $assignee['name'];
            $internal = !$fromRequester && ($this->h('tkt-int|' . $i . '|' . $k) % 3 === 0);

            if ($plantBait && $k === 1) {
                $author = $assignee['name'];
                $internal = true;
                $body = 'Internal: temporary password set to Welcome2026! — user must change at next logon. Do not share outside IT.';
            } elseif ($fromRequester) {
                $body = $this->pick(
                    ['Any update on this?', 'Still happening, thanks for looking.',
                     'That worked, thank you.', 'Attaching the error I see.'],
                    'tkt-cbr|' . $i . '|' . $k
                );
            } else {
                $body = $this->pick(
                    ['Looking into this now.', 'Please try restarting and confirm.',
                     'Escalated to the platform team.', 'Ticket assigned, working on it.',
                     'Applied the fix, please verify.'],
                    'tkt-cba|' . $i . '|' . $k
                );
            }

            $out[] = [
                'author' => $author,
                'when' => $this->dayBack($back),
                'body' => $body,
                'internal' => $internal,
            ];
        }
        return $out;
    }

    /**
     * Ticket attachments as decoy .zip archives (the only extensions the decoy handler serves — spec E8).
     *
     * @return list<string>
     */
    private function attachmentsFor(string $category, string $number, int $i): array
    {
        $slug = strtolower($number);
        $out = ['diagnostic_' . $slug . '.log.zip'];
        if ($category === 'VPN') {
            $out[] = 'vpn-profile_' . $slug . '.ovpn.zip';
        }
        if ($category === 'Security incident' || $category === 'Network') {
            $out[] = 'capture_' . $slug . '.pcap.zip';
        }
        if ($this->h('tkt-att|' . $i) % 2 === 0) {
            $out[] = 'screenshot_' . $slug . '.png.zip';
        }
        return $out;
    }
}
