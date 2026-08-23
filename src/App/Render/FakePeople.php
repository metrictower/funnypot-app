<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * Seeded fake-person generator for the LLM-shell fake pages (user tables, admin lists, audit
 * logs). Every value is a pure function of (seed, key) — same inputs always produce the same
 * person, so a page rendered twice for one deployment shows the same row, while two different
 * deployments (different seeds) or two different rows (different keys) diverge.
 *
 * PHP 7.3-COMPATIBLE ON PURPOSE: this class is a candidate for promotion into funnypot-core
 * (PHP 7.3), so it avoids match expressions, constructor property promotion, enums, named
 * arguments, and readonly properties — plain static methods + arrays + hash()/hexdec()/substr()
 * only. (Scalar/return type declarations and declare(strict_types=1) are PHP 7.0+ and fine here.)
 *
 * The name dictionaries are hand-authored (categories/shapes learned from fakerphp.org as a
 * reference, not copied) per the project's learn-don't-vendor rule — no third-party data files
 * are pulled in.
 */
final class FakePeople
{
    private const FIRST_NAMES = [
        'James', 'Mary', 'Robert', 'Patricia', 'John', 'Jennifer', 'Michael', 'Linda',
        'David', 'Elizabeth', 'William', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica',
        'Thomas', 'Sarah', 'Charles', 'Karen', 'Daniel', 'Nancy', 'Matthew', 'Lisa',
        'Anthony', 'Betty', 'Mark', 'Margaret', 'Donald', 'Sandra', 'Steven', 'Ashley',
        'Paul', 'Kimberly', 'Andrew', 'Emily', 'Joshua', 'Donna', 'Kenneth', 'Michelle',
        'Kevin', 'Carol', 'Brian', 'Amanda', 'George', 'Melissa', 'Edward', 'Deborah',
        'Ronald', 'Stephanie', 'Timothy', 'Rebecca', 'Jason', 'Sharon', 'Jeffrey', 'Laura',
        'Ryan', 'Cynthia', 'Jacob', 'Kathleen', 'Gary', 'Amy', 'Nicholas', 'Angela',
        'Priya', 'Wei', 'Fatima', 'Hiroshi', 'Elena', 'Sven', 'Aisha', 'Diego',
        'Yuki', 'Mateo', 'Ingrid', 'Kwame', 'Noor', 'Liam', 'Sofia', 'Omar',
    ];

    private const LAST_NAMES = [
        'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
        'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson', 'Thomas',
        'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson', 'White',
        'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson', 'Walker', 'Young',
        'Allen', 'King', 'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill', 'Flores',
        'Green', 'Adams', 'Nelson', 'Baker', 'Hall', 'Rivera', 'Campbell', 'Mitchell',
        'Carter', 'Roberts', 'Gomez', 'Phillips', 'Evans', 'Turner', 'Diaz', 'Parker',
        'Cruz', 'Edwards', 'Collins', 'Reyes', 'Stewart', 'Morris', 'Morales', 'Murphy',
        'Kowalski', 'Muller', 'Andersen', 'Fitzgerald', 'Costa', 'Novak', 'Haddad', 'Okafor',
        'Petrov', 'Suzuki', 'Ivanova', 'Larsen', 'Bianchi', 'Dubois', 'Sato', 'Weber',
    ];

    private const JOB_TITLES = [
        'Software Engineer', 'Systems Administrator', 'Product Manager', 'Data Analyst',
        'DevOps Engineer', 'QA Engineer', 'Support Specialist', 'Marketing Manager',
        'Sales Representative', 'Account Manager', 'HR Coordinator', 'Finance Analyst',
        'Operations Manager', 'Security Engineer', 'Database Administrator', 'IT Manager',
        'Customer Success Manager', 'Technical Writer', 'UX Designer', 'Project Coordinator',
    ];

    private const CITIES = [
        'Springfield', 'Riverside', 'Franklin', 'Georgetown', 'Clinton', 'Salem', 'Fairview',
        'Madison', 'Ashland', 'Burlington', 'Manchester', 'Arlington', 'Milton', 'Auburn',
        'Dover', 'Greenville', 'Kingston', 'Oxford', 'Chester', 'Lexington',
    ];

    private function __construct()
    {
    }

    /**
     * A deterministic, coherent fake person for (seed, key): same args always return the same
     * first/last/full/userName. Different keys (e.g. per table row) draw independent sub-hashes
     * for first vs last so the two vary independently rather than moving in lockstep.
     *
     * @return array{first:string,last:string,full:string,userName:string}
     */
    public static function person(int $seed, string $key): array
    {
        $first = self::FIRST_NAMES[self::index($seed, $key . '|first', count(self::FIRST_NAMES))];
        $last = self::LAST_NAMES[self::index($seed, $key . '|last', count(self::LAST_NAMES))];
        $full = $first . ' ' . $last;
        $userName = self::sanitizeLocal(strtolower($first[0] . '.' . $last));

        return [
            'first' => $first,
            'last' => $last,
            'full' => $full,
            'userName' => $userName,
        ];
    }

    /**
     * `{userName}@{domain}`, sanitized/lowercased on both halves so the result is a well-formed
     * address regardless of what's passed in (a persona domain is already clean, but this stays
     * safe if called with arbitrary input).
     *
     * @param array{first:string,last:string,full:string,userName:string} $person
     */
    public static function email(array $person, string $domain): string
    {
        $local = self::sanitizeLocal(strtolower($person['userName']));
        $host = strtolower(trim($domain));

        return $local . '@' . $host;
    }

    public static function jobTitle(int $seed, string $key): string
    {
        return self::JOB_TITLES[self::index($seed, $key . '|job', count(self::JOB_TITLES))];
    }

    public static function city(int $seed, string $key): string
    {
        return self::CITIES[self::index($seed, $key . '|city', count(self::CITIES))];
    }

    /** A private-range-looking IPv4, deterministic per (seed,key): 10.x.x.x with each octet
     *  independently seed-derived so two keys don't share an obviously-sequential address. */
    public static function ipv4(int $seed, string $key): string
    {
        $h = self::hash($seed, $key . '|ipv4');

        return '10.' . (hexdec(substr($h, 0, 2)) % 256) . '.' . (hexdec(substr($h, 2, 2)) % 256) . '.' . (hexdec(substr($h, 4, 2)) % 256);
    }

    /** A deterministic 'Y-m-d' date, offset back from $reference (a fixed epoch by default, so
     *  the result is a pure function of the args rather than wall-clock time) by 0-729 days. */
    public static function date(int $seed, string $key, int $reference = 1735689600): string
    {
        $offsetDays = self::index($seed, $key . '|date', 730);

        return gmdate('Y-m-d', $reference - ($offsetDays * 86400));
    }

    /** Sub-hash index into a dictionary of size $count, independently keyed by $field so two
     *  fields (e.g. first vs last name) never move in lockstep for the same seed. */
    private static function index(int $seed, string $field, int $count): int
    {
        return (int) (hexdec(substr(self::hash($seed, $field), 0, 8)) % $count);
    }

    private static function hash(int $seed, string $field): string
    {
        return hash('sha256', $seed . '|person|' . $field);
    }

    /** Strip everything outside [a-z0-9.] so a userName/email local-part is always a clean,
     *  realistic-looking token even if a dictionary entry ever carried an odd character. */
    private static function sanitizeLocal(string $s): string
    {
        return (string) preg_replace('/[^a-z0-9.]/', '', $s);
    }
}
