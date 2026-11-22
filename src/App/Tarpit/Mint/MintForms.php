<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * The true validation rules of the account forms. Every rule is a fixed pattern; nothing here builds
 * a pattern from request bytes. A failing value is reported by a message key and is never echoed.
 * The charsets exclude every character HTML or JSON would escape, so a value that passes is stored
 * and rendered verbatim (still escaped at render, as a second wall).
 */
final class MintForms
{
    public const USERNAME = '/\A[A-Za-z0-9][A-Za-z0-9_-]{1,38}\z/';
    public const EMAIL = '/\A[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,63}\.[A-Za-z]{2,24}\z/';
    public const TEXT = '/\A[A-Za-z0-9 _.:@+=,\/-]*\z/';
    public const URL = '/\A[A-Za-z0-9:\/._~?&=%+-]*\z/';
    public const URL_MAX = 200;

    /** Form value => days (0 = never, which the company refuses). */
    public const EXPIRATIONS = ['7' => 7, '30' => 30, '60' => 60, '90' => 90, 'none' => 0];

    private const HOST = '[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63}){0,8}';
    private const PORT = '(:[0-9]{1,5})?';
    private const REST = '(/[A-Za-z0-9\/._~?&=%+-]*)?';

    /**
     * The only callback shapes an OAuth application may register: https anywhere, or plain http on
     * the two IPv4/name loopback spellings. Validation and the engine-clean test both iterate this
     * one constant. IPv6 literals are not supported: their brackets fail the URL charset.
     */
    public const CALLBACK_FORMS = [
        'https' => [
            'pattern' => '#\Ahttps://' . self::HOST . self::PORT . self::REST . '\z#',
            'examples' => [
                'https://app.example.com/cb',
                'https://app.example.com:8443/oauth/callback',
                'https://app.example.com/oauth/callback?x=1',
                'https://app.example.com/oauth/callback?x=1&y=2',
                'https://cb.example.org/~user/hook',
                'https://10.0.0.5/cb',
                'https://192.168.1.20:8443/callback',
                'https://app.example.com/oauth/callback/',
                'https://localhost:8443/cb',
            ],
        ],
        'localhost' => [
            'pattern' => '#\Ahttp://localhost' . self::PORT . self::REST . '\z#',
            'examples' => ['http://localhost/cb', 'http://localhost:8080/cb', 'http://localhost:3000/auth/callback?x=1'],
        ],
        'loopback' => [
            'pattern' => '#\Ahttp://127\.0\.0\.1' . self::PORT . self::REST . '\z#',
            'examples' => ['http://127.0.0.1/cb', 'http://127.0.0.1:8080/cb', 'http://127.0.0.1:5000/oauth2/callback?a=b&c=d'],
        ],
    ];

    /** Spellings that look like callbacks but are refused (kept as negative fixtures). */
    public const REFUSED_CALLBACKS = ['http://[::1]:8080/cb', 'http://[::1]/cb'];

    private const HOMEPAGE = '#\Ahttps?://' . self::HOST . self::PORT . self::REST . '\z#';

    public static function validCallback(string $url): bool
    {
        if ($url === '' || strlen($url) > self::URL_MAX || preg_match(self::URL, $url) !== 1) {
            return false;
        }
        foreach (self::CALLBACK_FORMS as $form) {
            if (preg_match($form['pattern'], $url) === 1) {
                return true;
            }
        }

        return false;
    }

    public static function validHomepage(string $url): bool
    {
        return $url !== '' && strlen($url) <= self::URL_MAX && preg_match(self::URL, $url) === 1 && preg_match(self::HOMEPAGE, $url) === 1;
    }

    /**
     * A free-text field in the shared charset: null when fine, else the message key suffix. Only an
     * empty or spaces-only value is blank; anything else, control characters included, has to pass
     * the charset, so nothing JSON or HTML would escape is ever stored.
     */
    public static function text(?string $v, int $max, bool $required): ?string
    {
        if ($v === null || trim($v, ' ') === '') {
            return $required ? 'blank' : null;
        }
        if (strlen($v) > $max) {
            return 'long';
        }

        return preg_match(self::TEXT, $v) === 1 ? null : 'charset';
    }

    /**
     * @param callable(string):bool $usernameTaken
     * @param callable(string):bool $emailTaken
     * @return array<string,string> field => message key
     */
    public static function join(?string $username, ?string $email, ?string $password, ?string $confirm, callable $usernameTaken, callable $emailTaken): array
    {
        $errors = [];
        if ($username === null || preg_match(self::USERNAME, $username) !== 1) {
            $errors['username'] = 'username_invalid';
        } elseif ($usernameTaken($username) || MintRoutes::coreKeyed($username)) {
            // A name the profile URL could not serve is reserved, like any taken one.
            $errors['username'] = 'username_taken';
        }
        if ($email === null || strlen($email) > 153 || preg_match(self::EMAIL, $email) !== 1) {
            $errors['email'] = 'email_invalid';
        } elseif ($emailTaken($email)) {
            $errors['email'] = 'email_taken';
        }
        $len = $password === null ? 0 : strlen($password);
        if ($len < 8 || $len > 72) {
            $errors['password'] = 'password_length';
        } elseif ($confirm === null || !hash_equals($password, $confirm)) {
            $errors['password_confirmation'] = 'password_mismatch';
        }

        return $errors;
    }

    /**
     * The field stage of a token mint. Scopes arrive already type-checked: null means the field was
     * not a list of strings, which counts as none.
     *
     * @param list<string>|null $scopes
     * @param callable(string):bool $noteTaken
     * @return array<string,string>
     */
    public static function token(?string $note, ?string $expiration, ?array $scopes, callable $noteTaken, array $extraScopes = []): array
    {
        $errors = [];
        $n = self::text($note, 100, true);
        if ($n !== null) {
            $errors['note'] = 'note_' . $n;
        } elseif ($noteTaken((string) $note)) {
            $errors['note'] = 'note_taken';
        }
        if ($scopes === null || $scopes === []) {
            $errors['scopes'] = 'scopes_none';
        } else {
            foreach ($scopes as $s) {
                if (!ScopeSet::known($s, $extraScopes)) {
                    $errors['scopes'] = 'scopes_unknown';
                    break;
                }
            }
        }
        if ($expiration === null || !array_key_exists($expiration, self::EXPIRATIONS)) {
            $errors['expiration'] = 'expiration_bad';
        } elseif (self::EXPIRATIONS[$expiration] === 0) {
            $errors['expiration'] = 'expiration_none';
        }

        return $errors;
    }

    /**
     * @param callable(string):bool $nameTaken
     * @return array<string,string>
     */
    public static function app(?string $name, ?string $homepage, ?string $callback, ?string $description, callable $nameTaken): array
    {
        $errors = [];
        $n = self::text($name, 100, true);
        if ($n !== null) {
            $errors['name'] = 'app_name_' . $n;
        } elseif ($nameTaken((string) $name)) {
            $errors['name'] = 'app_name_taken';
        }
        if ($homepage === null || !self::validHomepage($homepage)) {
            $errors['homepage_url'] = 'homepage_invalid';
        }
        if ($callback === null || !self::validCallback($callback)) {
            $errors['callback_url'] = 'callback_invalid';
        }
        $d = self::text($description, 200, false);
        if ($d !== null) {
            $errors['description'] = 'description_' . $d;
        }

        return $errors;
    }

    /** @return array<string,string> */
    public static function profile(?string $name, ?string $bio): array
    {
        $errors = [];
        foreach (['name' => $name, 'bio' => $bio] as $field => $v) {
            $e = self::text($v, 160, false);
            if ($e !== null) {
                $errors[$field] = $field . '_' . $e;
            }
        }

        return $errors;
    }
}
