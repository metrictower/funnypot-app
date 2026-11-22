<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

/**
 * A token-level reader of PHP source for the no-outbound checks. It never runs the code.
 *
 * extract() lists what a file can reach: the functions it calls, the classes it instantiates, the
 * static methods it calls and the classes it extends or implements, each resolved through the file's
 * namespace and `use` imports. violations() applies the SSRF namespace allowlist to the same tokens
 * and names every rule a file breaks. Comments and strings never count as code here.
 */
final class CallScan
{
    /** Functions that take a callable, and the argument position it sits in. */
    public const CALLABLE_ARGS = [
        'array_map' => 0, 'array_filter' => 1, 'usort' => 1, 'uasort' => 1, 'uksort' => 1, 'array_reduce' => 1,
        'preg_replace_callback' => 1, 'array_walk' => 1, 'array_walk_recursive' => 1,
    ];

    public const SUPERGLOBALS = ['$_SERVER', '$_GET', '$_POST', '$_COOKIE', '$_FILES', '$_ENV', '$_REQUEST', '$_SESSION', '$GLOBALS'];

    /** @return list<array{0:int|string,1:string,2:int}> significant tokens: [id, text, line] */
    public static function tokens(string $code): array
    {
        $out = [];
        foreach (token_get_all($code, TOKEN_PARSE) as $t) {
            if (is_array($t)) {
                if (in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG], true)) {
                    continue;
                }
                $out[] = [$t[0], $t[1], $t[2]];
            } else {
                $out[] = [$t, $t, 0];
            }
        }

        return $out;
    }

    /**
     * @return array{namespace:string,uses:array<string,string>,fuses:array<string,string>}
     */
    private static function context(array $toks): array
    {
        $ns = '';
        $uses = [];
        $fuses = [];
        $n = count($toks);
        $depth = 0;
        for ($i = 0; $i < $n; $i++) {
            [$id, $text] = $toks[$i];
            if ($id === '{') {
                $depth++;
            } elseif ($id === '}') {
                $depth--;
            }
            if ($id === T_NAMESPACE && isset($toks[$i + 1]) && in_array($toks[$i + 1][0], [T_STRING, T_NAME_QUALIFIED], true)) {
                $ns = $toks[$i + 1][1];
            }
            if ($id === T_USE && $depth === 0) {
                $kind = 'class';
                $j = $i + 1;
                if (($toks[$j][0] ?? null) === T_FUNCTION) {
                    $kind = 'function';
                    $j++;
                } elseif (($toks[$j][0] ?? null) === T_CONST) {
                    $kind = 'const';
                    $j++;
                }
                while ($j < $n && $toks[$j][0] !== ';') {
                    $name = ltrim($toks[$j][1], '\\');
                    $alias = substr($name, (int) strrpos('\\' . $name, '\\'));
                    if (($toks[$j + 1][0] ?? null) === T_AS) {
                        $alias = $toks[$j + 2][1];
                        $j += 2;
                    }
                    if ($kind === 'class') {
                        $uses[strtolower($alias)] = $name;
                    } elseif ($kind === 'function') {
                        $fuses[strtolower($alias)] = $name;
                    }
                    $j++;
                    if (($toks[$j][0] ?? null) === ',') {
                        $j++;
                    }
                }
            }
        }

        return ['namespace' => $ns, 'uses' => $uses, 'fuses' => $fuses];
    }

    private static function resolveClass(string $name, array $ctx): string
    {
        if ($name === '' || in_array(strtolower($name), ['self', 'static', 'parent'], true)) {
            return strtolower($name);
        }
        if ($name[0] === '\\') {
            return substr($name, 1);
        }
        $first = strtolower(explode('\\', $name)[0]);
        if (isset($ctx['uses'][$first])) {
            $rest = substr($name, strlen($first));

            return $ctx['uses'][$first] . $rest;
        }

        return $ctx['namespace'] !== '' ? $ctx['namespace'] . '\\' . $name : $name;
    }

    private static function resolveFunction(string $name, array $ctx): string
    {
        $bare = ltrim($name, '\\');
        if (isset($ctx['fuses'][strtolower($bare)])) {
            return strtolower($ctx['fuses'][strtolower($bare)]);
        }

        return strtolower($bare);
    }

    private const NAME_TOKENS = [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE];

    /**
     * What a file can reach.
     *
     * @return array{calls:list<string>,new:list<string>,static:list<string>,extends:list<string>}
     */
    public static function extract(string $code): array
    {
        $toks = self::tokens($code);
        $ctx = self::context($toks);
        $calls = $new = $static = $extends = [];
        $n = count($toks);
        for ($i = 0; $i < $n; $i++) {
            [$id, $text] = $toks[$i];
            $prev = $toks[$i - 1][0] ?? null;
            $next = $toks[$i + 1][0] ?? null;
            if (in_array($id, self::NAME_TOKENS, true) && $next === '(' && !in_array($prev, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST, T_FN], true)) {
                $calls[self::resolveFunction($text, $ctx)] = true;
            }
            if ($id === T_NEW) {
                $t = $toks[$i + 1] ?? [null, ''];
                if (in_array($t[0], self::NAME_TOKENS, true) || $t[0] === T_STATIC) {
                    $new[self::resolveClass($t[1], $ctx)] = true;
                } elseif ($t[0] === T_CLASS) {
                    $new['class@anonymous'] = true;
                } else {
                    $new['(dynamic)'] = true;
                }
            }
            if ($id === T_DOUBLE_COLON && in_array($prev, [...self::NAME_TOKENS, T_STATIC], true)
                && ($toks[$i + 1][0] ?? null) === T_STRING && ($toks[$i + 2][0] ?? null) === '(') {
                $static[self::resolveClass($toks[$i - 1][1], $ctx) . '::' . strtolower($toks[$i + 1][1])] = true;
            }
            if (in_array($id, [T_EXTENDS, T_IMPLEMENTS], true)) {
                for ($j = $i + 1; $j < $n && !in_array($toks[$j][0], ['{', T_IMPLEMENTS], true); $j++) {
                    if (in_array($toks[$j][0], self::NAME_TOKENS, true)) {
                        $extends[self::resolveClass($toks[$j][1], $ctx)] = true;
                    }
                }
            }
        }
        $sorted = static function (array $set): array {
            $k = array_keys($set);
            sort($k);

            return $k;
        };

        return ['calls' => $sorted($calls), 'new' => $sorted($new), 'static' => $sorted($static), 'extends' => $sorted($extends)];
    }

    /**
     * The allowlist's verdict on one file: each broken rule as "rule-id: detail @line".
     *
     * @param array{functions:list<string>,classes:list<string>,static:list<string>,parents:list<string>,own:list<string>,store_only:array<string,list<string>>} $allow
     * @return list<string>
     */
    public static function violations(string $code, string $file, array $allow): array
    {
        $toks = self::tokens($code);
        $ctx = self::context($toks);
        $out = [];
        $own = static function (string $fqcn) use ($allow): bool {
            foreach ($allow['own'] as $prefix) {
                if (strncasecmp($fqcn, $prefix, strlen($prefix)) === 0) {
                    return true;
                }
            }

            return false;
        };
        $functions = array_flip(array_map('strtolower', $allow['functions']));
        $classes = array_flip(array_map('strtolower', $allow['classes']));
        $statics = array_flip(array_map('strtolower', $allow['static']));
        $parents = array_flip(array_map('strtolower', $allow['parents']));
        $base = basename($file);
        $n = count($toks);
        foreach (token_get_all($code, TOKEN_PARSE) as $raw) {
            if ($raw === '`') {
                $out[] = 'backtick';
            }
            if (is_array($raw) && $raw[0] === T_INLINE_HTML) {
                $out[] = 'output: inline html @' . $raw[2];
            }
        }
        $stack = [];
        for ($i = 0; $i < $n; $i++) {
            [$id, $text, $line] = $toks[$i];
            $prev = $toks[$i - 1][0] ?? null;
            $next = $toks[$i + 1][0] ?? null;
            $at = ' @' . $line;
            $inArgs = $stack !== [] && $stack[count($stack) - 1] === '(';
            if (in_array($id, ['(', '[', '{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true)) {
                $stack[] = $id === '(' ? '(' : ($id === '[' ? '[' : '{');
            } elseif (in_array($id, [')', ']', '}'], true)) {
                array_pop($stack);
                $inArgs = $stack !== [] && $stack[count($stack) - 1] === '(';
            }
            // A callee that is not a literal name: a string literal, an array element or a computed
            // method name called directly.
            if ($id === T_CONSTANT_ENCAPSED_STRING && $next === '(') {
                $out[] = 'dynamic_call: string literal' . $at;
            }
            if ($id === ']' && $next === '(') {
                $out[] = 'dynamic_call: array element' . $at;
            }
            if ($id === T_DOUBLE_COLON && $next === '{') {
                $out[] = 'dynamic_call: computed static method' . $at;
            }
            // A string naming a function or a Class::method, or a [target, 'method'] pair, passed as an
            // argument to any function or method is a callable whatever the callee does with it.
            if ($inArgs && $id === T_CONSTANT_ENCAPSED_STRING && in_array($prev, ['(', ','], true) && in_array($next, [')', ','], true)) {
                $value = stripcslashes(substr($text, 1, -1));
                if (preg_match('/\A\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*(?:::[A-Za-z_]\w*)?\z/', $value) === 1
                    && (str_contains($value, '::') || function_exists(ltrim($value, '\\')))) {
                    $out[] = 'string_callable: ' . $value . $at;
                }
            }
            if ($inArgs && $id === '[' && in_array($prev, ['(', ','], true) && self::arrayCallable($toks, $i)) {
                $out[] = 'array_callable' . $at;
            }
            switch (true) {
                case $id === T_EVAL:
                    $out[] = 'eval' . $at;
                    break;
                case in_array($id, [T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true):
                    $out[] = 'include' . $at;
                    break;
                case $id === T_GOTO:
                    $out[] = 'goto' . $at;
                    break;
                case $id === T_EXIT:
                    $out[] = 'exit' . $at;
                    break;
                case in_array($id, [T_ECHO, T_PRINT], true):
                    $out[] = 'output: ' . strtolower($text) . $at;
                    break;
                case $id === T_VARIABLE && in_array($text, self::SUPERGLOBALS, true):
                    $out[] = 'superglobal: ' . $text . $at;
                    break;
                case $id === '$':
                    $out[] = 'variable_variable' . $at;
                    break;
            }
            if ($id === T_VARIABLE && $next === '(') {
                $out[] = 'variable_call: ' . $text . $at;
            }
            if ($id === ')' && $next === '(') {
                $out[] = 'variable_call: (expr)()' . $at;
            }
            if (in_array($id, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true) && $next === T_VARIABLE) {
                $out[] = 'variable_method' . $at;
            }
            if (in_array($id, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true) && $next === '{') {
                $out[] = 'variable_method' . $at;
            }
            if ($id === T_DOUBLE_COLON && $next === T_VARIABLE && ($toks[$i + 2][0] ?? null) === '(') {
                $out[] = 'variable_static' . $at;
            }
            if ($id === T_DOUBLE_COLON && $prev === T_VARIABLE) {
                $out[] = 'variable_static' . $at;
            }
            if (in_array($id, self::NAME_TOKENS, true) && $next === '(' && !in_array($prev, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST, T_FN], true)) {
                $fn = self::resolveFunction($text, $ctx);
                if (!isset($functions[$fn])) {
                    $out[] = 'function: ' . $fn . $at;
                } elseif ($fn === 'error_log' && self::argCount($toks, $i + 1) !== 1) {
                    $out[] = 'error_log_type' . $at;
                } elseif (isset(self::CALLABLE_ARGS[$fn]) && !self::callableArgSafe($toks, $i + 1, self::CALLABLE_ARGS[$fn], $functions)) {
                    $out[] = 'string_callable: ' . $fn . $at;
                }
            }
            if ($id === T_NEW) {
                $t = $toks[$i + 1] ?? [null, ''];
                if ($t[0] === T_CLASS) {
                    $out[] = 'anonymous_class' . $at;
                } elseif (in_array($t[0], self::NAME_TOKENS, true) || $t[0] === T_STATIC) {
                    $cls = self::resolveClass($t[1], $ctx);
                    if (!in_array($cls, ['self', 'static'], true) && !$own($cls) && !isset($classes[strtolower($cls)])) {
                        $out[] = 'new: ' . $cls . $at;
                    }
                } else {
                    $out[] = 'new_dynamic' . $at;
                }
            }
            if ($id === T_DOUBLE_COLON && in_array($prev, [...self::NAME_TOKENS, T_STATIC], true)
                && ($toks[$i + 1][0] ?? null) === T_STRING && ($toks[$i + 2][0] ?? null) === '(') {
                $cls = self::resolveClass($toks[$i - 1][1], $ctx);
                $pair = strtolower($cls . '::' . $toks[$i + 1][1]);
                if (!in_array($cls, ['self', 'static', 'parent'], true) && !$own($cls) && !isset($statics[$pair])) {
                    $out[] = 'static: ' . $cls . '::' . $toks[$i + 1][1] . $at;
                }
                foreach ($allow['store_only'] as $storePair => $files) {
                    if ($pair === strtolower($storePair) && !in_array($base, $files, true)) {
                        $out[] = 'static: ' . $cls . '::' . $toks[$i + 1][1] . ' outside the store' . $at;
                    }
                }
            }
            if (in_array($id, [T_EXTENDS, T_IMPLEMENTS], true)) {
                for ($j = $i + 1; $j < $n && !in_array($toks[$j][0], ['{', T_IMPLEMENTS], true); $j++) {
                    if (in_array($toks[$j][0], self::NAME_TOKENS, true)) {
                        $cls = self::resolveClass($toks[$j][1], $ctx);
                        if (!$own($cls) && !isset($parents[strtolower($cls)])) {
                            $out[] = 'extends: ' . $cls . $at;
                        }
                    }
                }
            }
        }

        return $out;
    }

    /** The number of top-level arguments of the call whose `(` is at $open. */
    private static function argCount(array $toks, int $open): int
    {
        $depth = 0;
        $args = 0;
        $seen = false;
        for ($j = $open; $j < count($toks); $j++) {
            $t = $toks[$j][0];
            if (in_array($t, ['(', '[', '{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true)) {
                $depth++;
                if ($depth === 1) {
                    continue;
                }
            } elseif (in_array($t, [')', ']', '}'], true)) {
                $depth--;
                if ($depth === 0) {
                    return $seen ? $args + 1 : 0;
                }
            }
            if ($depth === 1 && $t === ',') {
                $args++;
                continue;
            }
            if ($depth >= 1) {
                $seen = true;
            }
        }

        return $args;
    }

    /**
     * Whether the callable argument at $pos is a closure, an arrow function or a first-class callable
     * of an allowlisted name (a string or array callable is not).
     */
    /**
     * Whether the array literal opening at $open is a [target, 'method'] pair: two elements, the second
     * a method-shaped string, the first an object or class (a variable, a `new`, an `X::class`, or a
     * string naming a class). A pair of plain data words, or a spread, is not one.
     */
    private static function arrayCallable(array $toks, int $open): bool
    {
        $first = [];
        $depth = 0;
        $j = $open + 1;
        for (; $j < count($toks); $j++) {
            $t = $toks[$j][0];
            if (in_array($t, ['(', '[', '{'], true)) {
                $depth++;
            } elseif (in_array($t, [')', ']', '}'], true)) {
                if ($depth === 0) {
                    return false;
                }
                $depth--;
            } elseif ($t === ',' && $depth === 0) {
                break;
            }
            $first[] = $toks[$j];
        }
        $method = $toks[$j + 1] ?? [null, ''];
        if ($first === [] || $first[0][0] === T_ELLIPSIS || $method[0] !== T_CONSTANT_ENCAPSED_STRING || ($toks[$j + 2][0] ?? null) !== ']'
            || preg_match('/\A[A-Za-z_]\w*\z/', substr($method[1], 1, -1)) !== 1) {
            return false;
        }
        if (count($first) === 1 && $first[0][0] === T_CONSTANT_ENCAPSED_STRING) {
            $target = substr($first[0][1], 1, -1);

            return str_contains($target, '\\') || preg_match('/\A[A-Z]/', $target) === 1
                || ($target !== '' && (class_exists($target, false) || interface_exists($target, false)));
        }
        foreach ($first as $k => $t) {
            if ($t[0] === T_VARIABLE || $t[0] === T_NEW || ($t[0] === T_DOUBLE_COLON && strtolower((string) ($first[$k + 1][1] ?? '')) === 'class')) {
                return true;
            }
        }

        return false;
    }

    private static function callableArgSafe(array $toks, int $open, int $pos, array $functions): bool
    {
        $depth = 0;
        $arg = 0;
        for ($j = $open; $j < count($toks); $j++) {
            $t = $toks[$j][0];
            if (in_array($t, ['(', '[', '{'], true)) {
                $depth++;
                if ($depth === 1) {
                    continue;
                }
            } elseif (in_array($t, [')', ']', '}'], true)) {
                $depth--;
                if ($depth === 0) {
                    return true;
                }
            }
            if ($depth === 1 && $t === ',') {
                $arg++;
                continue;
            }
            if ($depth === 1 && $arg === $pos) {
                if (in_array($t, [T_FUNCTION, T_FN, T_STATIC], true)) {
                    return true;
                }
                if (in_array($t, self::NAME_TOKENS, true) && ($toks[$j + 1][0] ?? null) === '(' && ($toks[$j + 2][0] ?? null) === T_ELLIPSIS) {
                    return isset($functions[strtolower(ltrim($toks[$j][1], '\\'))]);
                }

                return false;
            }
        }

        return true;
    }
}
