<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * Model-supplied page content, decoded and made safe for the renderer: every field has a typed
 * default and every list is capped, so a thin or mistyped model response can never make the shell
 * throw (the LLM tier must only ever upgrade a 404, never 500).
 */
final class PageSlots
{
    /** Placeholders the model may emit instead of a real secret or a real person; resolved to a
     *  persona-coherent fake before any skin renders — the model never invents the actual value. */
    public const MARKERS = ['APITOKEN', 'EMAIL', 'AWSKEY', 'NAME', 'USERNAME'];

    private function __construct(
        private string $appName,
        private string $pageTitle,
        private string $heading,
        private string $intro,
        /** @var list<string> */ private array $navItems,
        /** @var list<string> */ private array $tableCols,
        /** @var list<list<string>> */ private array $tableRows,
        /** @var list<string> */ private array $formFields,
        private string $flash,
        private string $footerNote,
    ) {
    }

    /** @param array<mixed> $d */
    public static function fromArray(array $d): self
    {
        return new self(
            self::str($d, 'app_name'),
            self::str($d, 'page_title'),
            self::str($d, 'heading'),
            self::str($d, 'intro'),
            self::strList($d['nav_items'] ?? null, 5),
            self::strList(is_array($d['table'] ?? null) ? ($d['table']['cols'] ?? null) : null, 4),
            self::rows(is_array($d['table'] ?? null) ? ($d['table']['rows'] ?? null) : null),
            self::strList($d['form_fields'] ?? null, 4),
            self::str($d, 'flash'),
            self::str($d, 'footer_note'),
        );
    }

    public function appName(): string { return $this->appName; }
    public function pageTitle(): string { return $this->pageTitle; }
    public function heading(): string { return $this->heading; }
    public function intro(): string { return $this->intro; }
    /** @return list<string> */ public function navItems(): array { return $this->navItems; }
    /** @return list<string> */ public function tableCols(): array { return $this->tableCols; }
    /** @return list<list<string>> */ public function tableRows(): array { return $this->tableRows; }
    /** @return list<string> */ public function formFields(): array { return $this->formFields; }
    public function flash(): string { return $this->flash; }
    public function footerNote(): string { return $this->footerNote; }

    public function hasBody(): bool
    {
        return $this->intro !== '' || $this->navItems !== [] || $this->tableRows !== []
            || $this->formFields !== [];
    }

    /**
     * Resolves every model string slot in place, once, before any skin renders — so a marker like
     * APITOKEN never leaks as a literal word into whichever skin happens to handle a given path.
     * tableCols is left untouched: those are model-chosen header labels, never a secret slot.
     */
    public function resolveMarkers(VisualPersona $persona): self
    {
        return new self(
            self::mark($this->appName, $persona, 'appName'),
            self::mark($this->pageTitle, $persona, 'pageTitle'),
            self::mark($this->heading, $persona, 'h'),
            self::mark($this->intro, $persona, 'intro'),
            self::markList($this->navItems, $persona, 'nav'),
            $this->tableCols,
            self::markRows($this->tableRows, $persona),
            self::markList($this->formFields, $persona, 'f'),
            self::mark($this->flash, $persona, 'flash'),
            self::mark($this->footerNote, $persona, 'footerNote'),
        );
    }

    /** A value equal (after trim) to a MARKERS entry becomes a persona-coherent fake; anything else
     *  passes through unchanged. $key keeps distinct slots/cells from resolving to the same fake —
     *  in a single (non-row) context it also doubles as the person key, so within one slot NAME/
     *  USERNAME/EMAIL never contradict each other because callers are expected to reuse one $salt
     *  per logical field group; markRows() is the context that actually varies the person per row. */
    private static function mark(string $v, VisualPersona $persona, string $salt): string
    {
        $trimmed = trim($v);
        if (!in_array($trimmed, self::MARKERS, true)) {
            return $v;
        }
        return self::resolveMarker($trimmed, $persona, $salt);
    }

    /** Resolves one already-validated marker to its persona-coherent fake value, keyed by $key.
     *  Shared by mark() (single-context, keyed by the caller's salt) and markRows() (row-context,
     *  keyed by the row for NAME/USERNAME/EMAIL so they describe one coherent person, and by the
     *  cell for APITOKEN so tokens stay distinct within a row). The default arm keeps this total
     *  even if MARKERS ever grows a case this match doesn't yet cover — the LLM tier must never
     *  throw, only upgrade a 404. */
    private static function resolveMarker(string $marker, VisualPersona $persona, string $key): string
    {
        return match ($marker) {
            'APITOKEN' => $persona->fakeToken($key),
            'EMAIL' => $persona->personEmail($key),
            'AWSKEY' => $persona->awsKey(),
            'NAME' => $persona->person($key)['full'],
            'USERNAME' => $persona->person($key)['userName'],
            default => '',
        };
    }

    /** @param list<string> $items @return list<string> */
    private static function markList(array $items, VisualPersona $persona, string $prefix): array
    {
        $out = [];
        foreach ($items as $i => $item) {
            $out[] = self::mark($item, $persona, "{$prefix}{$i}");
        }
        return $out;
    }

    /**
     * Row-coherent: every row gets ONE person key ("row{$r}"), so a row's NAME/USERNAME/EMAIL all
     * describe the same fake person (personEmail() derives from person(), so the email local-part
     * matches the name/username in that same row) — different rows use different keys, so different
     * rows are different people and EMAIL varies per row instead of repeating one persona-wide
     * adminEmail(). APITOKEN keeps a per-cell key so tokens stay distinct within a row; AWSKEY
     * ignores the key entirely (one persona-wide fake key, same as before).
     *
     * @param list<list<string>> $rows @return list<list<string>>
     */
    private static function markRows(array $rows, VisualPersona $persona): array
    {
        $out = [];
        foreach ($rows as $r => $row) {
            $rowKey = "row{$r}";
            $newRow = [];
            foreach ($row as $c => $cell) {
                $trimmed = trim($cell);
                if (!in_array($trimmed, self::MARKERS, true)) {
                    $newRow[] = $cell;
                    continue;
                }
                $key = $trimmed === 'APITOKEN' ? "r{$r}c{$c}" : $rowKey;
                $newRow[] = self::resolveMarker($trimmed, $persona, $key);
            }
            $out[] = $newRow;
        }
        return $out;
    }

    /** @param array<mixed> $d */
    private static function str(array $d, string $k): string
    {
        $v = $d[$k] ?? null;
        return is_string($v) ? $v : '';
    }

    /** @param mixed $v @return list<string> */
    private static function strList($v, int $cap): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $item) {
            if (is_string($item)) {
                $out[] = $item;
            }
            if (count($out) >= $cap) {
                break;
            }
        }
        return $out;
    }

    /** @param mixed $v @return list<list<string>> */
    private static function rows($v): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $row) {
            $out[] = self::strList($row, 4);
            if (count($out) >= 3) {
                break;
            }
        }
        return $out;
    }
}
