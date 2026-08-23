<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * Segment-anchored path matching for resemblance skins. A raw str_contains() lets a token match as
 * a substring anywhere in the path — "admin" inside "/user/admin-notes" or "/administer" — which
 * misroutes an unrelated path to the wrong skin's `matches()`. These helpers instead split the path
 * into '/'-delimited segments, so a token only counts when it IS a segment (or the start of one),
 * never when it's merely buried inside a longer word. Pure and total: never throws, malformed or
 * empty input just yields false/[].
 */
final class PathSegments
{
    /** @return list<string> non-empty segments, e.g. "/admin/users/" -> ['admin', 'users'] */
    public static function of(string $path): array
    {
        return array_values(array_filter(explode('/', $path), static fn (string $s): bool => $s !== ''));
    }

    /** True when $segment is exactly one whole path segment (case-sensitive), at any position. */
    public static function has(string $path, string $segment): bool
    {
        return in_array($segment, self::of($path), true);
    }

    /** True when some path segment starts with $prefix (case-sensitive), at any position — for a
     *  family like WordPress's "wp-*" where the segment itself carries more than the bare token
     *  (wp-login.php, wp-admin, wp-content, ...). */
    public static function hasPrefixed(string $path, string $prefix): bool
    {
        foreach (self::of($path) as $seg) {
            if (str_starts_with($seg, $prefix)) {
                return true;
            }
        }
        return false;
    }

    /** True when the path's FIRST segment is exactly $segment and at least one more segment follows
     *  it — e.g. Grafana's "/d/<uid>" dashboard shape, which is only meaningful as the leading two
     *  segments of the path, not whenever "d" shows up as some later segment. */
    public static function startsWithSegmentThenMore(string $path, string $segment): bool
    {
        $segs = self::of($path);
        return count($segs) >= 2 && $segs[0] === $segment;
    }
}
