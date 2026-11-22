<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * The account surface's HTML pages, in the public sign-in page's palette with inline CSS and no
 * external assets. Every link and form action targets one of the surface's own paths or `/`; nothing
 * points at an admin console or off-site, and stored URLs are shown as text, never as links.
 *
 * Every dynamic value is escaped here, even though the form rules already restrict it to a charset
 * with nothing to escape. Values from a GET query or a path are never passed in.
 */
final class AccountPages
{
    public function __construct(private MintPersona $p)
    {
    }

    public static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** A message, with the persona's own fillers always available to it. */
    private function msg(string $key, array $vars = []): string
    {
        return self::e(MintVocabulary::text($key, $vars + ['company' => $this->p->company]));
    }

    // --- chrome ----------------------------------------------------------------------------------

    public function layout(string $title, string $main, bool $signedIn, ?string $notice = null): string
    {
        $c = self::e($this->p->company);
        $nav = $signedIn
            ? "<nav><a href='/settings/profile'>Profile</a><a href='/settings/security'>Security</a>"
                . "<a href='/settings/tokens'>Tokens</a><a href='/settings/applications'>OAuth apps</a>"
                . "<a href='/docs/api'>API docs</a><a href='/signout'>Sign out</a></nav>"
            : "<nav><a href='/docs/api'>API docs</a><a href='/'>Sign in</a></nav>";

        return '<!doctype html><html lang=en><head><meta charset=utf-8>'
            . "<meta name=viewport content='width=device-width,initial-scale=1'>"
            . '<title>' . self::e($title) . ' · ' . $c . '</title><style>' . self::css() . '</style></head><body>'
            . "<header class=top><a class=brand href='/'>" . $c . '</a>' . $nav . '</header>'
            . '<main class=wrap>' . ($notice !== null ? '<p class=note>' . self::e($notice) . '</p>' : '') . $main . '</main>'
            . '<footer>' . $c . ' account</footer></body></html>';
    }

    private static function css(): string
    {
        return 'body{font-family:system-ui,-apple-system,sans-serif;background:#f4f5f7;margin:0;color:#111}'
            . '.top{background:#fff;border-bottom:1px solid #e3e5e8;padding:.75rem 1.5rem;display:flex;align-items:center;gap:1.5rem}'
            . '.brand{font-weight:600;color:#111;text-decoration:none}.top nav{display:flex;gap:1rem;flex-wrap:wrap}'
            . '.top nav a{color:#333;text-decoration:none;font-size:.9rem}.wrap{max-width:760px;margin:2rem auto;padding:0 1rem}'
            . '.card{background:#fff;padding:1.5rem;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);margin:0 0 1rem}'
            . 'h1{font-size:1.25rem;margin:0 0 1rem}h2{font-size:1rem;margin:0 0 .75rem}'
            . 'label{display:block;margin:0 0 .75rem;font-size:.85rem;color:#333}'
            . 'input,select,textarea{display:block;width:100%;padding:.5rem;margin-top:.25rem;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}'
            . 'input[type=checkbox]{display:inline;width:auto;margin:0 .4rem 0 0}.scope{display:block;font-size:.85rem;margin:0 0 .4rem}'
            . 'button{padding:.55rem 1rem;background:#2563eb;color:#fff;border:0;border-radius:4px;cursor:pointer;font-size:.9rem}'
            . 'button.alt{background:#e3e5e8;color:#111}button.danger{background:#b91c1c}'
            . '.err{color:#b91c1c;font-size:.85rem;margin:.25rem 0 .75rem}.note{background:#eef4ff;border:1px solid #c7d7fe;padding:.6rem .8rem;border-radius:4px;font-size:.9rem}'
            . 'code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem;word-break:break-all}'
            . 'table{width:100%;border-collapse:collapse;font-size:.85rem}td,th{text-align:left;padding:.4rem;border-bottom:1px solid #eee}'
            . '.muted{color:#666;font-size:.85rem}.row{display:flex;gap:.5rem;align-items:center}footer{text-align:center;color:#888;font-size:.8rem;margin:2rem 0}';
    }

    private static function csrf(string $token): string
    {
        return "<input type=hidden name=csrf_token value='" . self::e($token) . "'>";
    }

    /** @param array<string,string> $errors */
    private function fieldError(array $errors, string $field): string
    {
        return isset($errors[$field]) ? '<p class=err>' . $this->msg($errors[$field]) . '</p>' : '';
    }

    /** @param array<string,string> $values */
    private function input(string $label, string $name, array $values, array $errors, string $type = 'text', string $extra = ''): string
    {
        $v = $type === 'password' ? '' : ($values[$name] ?? '');

        return '<label>' . self::e($label) . "<input type={$type} name={$name} value='" . self::e($v) . "'{$extra}></label>"
            . $this->fieldError($errors, $name);
    }

    private static function date(int $ts): string
    {
        return gmdate('M j, Y', $ts);
    }

    // --- pages -----------------------------------------------------------------------------------

    /** @param array<string,mixed> $a */
    public function home(array $a, ?string $notice): string
    {
        $tokens = count($a['k']);
        $apps = count($a['ap']);
        $main = '<div class=card><h1>Signed in as ' . self::e((string) $a['u']) . '</h1>'
            . '<p class=muted>Member of ' . self::e($this->p->company) . ' since ' . self::date((int) $a['c']) . '.</p></div>'
            . "<div class=card><h2>Developer tools</h2><p><a href='/settings/tokens'>Personal access tokens</a> ("
            . $tokens . ") · <a href='/settings/applications'>OAuth applications</a> (" . $apps . ')</p>'
            . "<p class=muted>Use a token with the API. See the <a href='/docs/api'>API documentation</a>.</p></div>"
            . "<div class=card><h2>Security</h2><p>Two-factor authentication is " . ($a['tf'] !== null ? 'on' : 'off')
            . ". <a href='/settings/security'>Manage</a></p></div>";

        return $this->layout('Account', $main, true, $notice);
    }

    /** @param array<string,string> $values @param array<string,string> $errors */
    public function join(string $csrf, array $values, array $errors, ?string $notice = null): string
    {
        $main = '<div class=card><h1>Create your ' . self::e($this->p->company) . ' account</h1>'
            . "<form method=post action='/join'>" . self::csrf($csrf)
            . $this->input('Username', 'username', $values, $errors, 'text', ' autocomplete=username')
            . $this->input('Email', 'email', $values, $errors, 'email', ' autocomplete=email')
            . $this->input('Password', 'password', $values, $errors, 'password', ' autocomplete=new-password')
            . $this->input('Confirm password', 'password_confirmation', $values, $errors, 'password', ' autocomplete=new-password')
            . '<button type=submit>Create account</button></form>'
            . "<p class=muted>Already have an account? <a href='/'>Sign in</a></p></div>";

        return $this->layout('Create account', $main, false, $notice);
    }

    public function signout(string $csrf): string
    {
        $main = "<div class=card><h1>Sign out</h1><form method=post action='/signout'>" . self::csrf($csrf)
            . '<p>Sign out of your account on this device?</p><button type=submit>Sign out</button></form></div>';

        return $this->layout('Sign out', $main, true);
    }

    /** @param array<string,mixed> $a @param array<string,string> $values @param array<string,string> $errors */
    public function profile(array $a, string $csrf, array $values, array $errors, ?string $notice): string
    {
        $values += ['name' => (string) $a['nm'], 'bio' => (string) $a['bi']];
        $main = '<div class=card><h1>Public profile</h1>'
            . '<p class=muted>Username: ' . self::e((string) $a['u']) . ' · Email: ' . self::e((string) $a['em']) . '</p>'
            . "<form method=post action='/settings/profile'>" . self::csrf($csrf)
            . $this->input('Name', 'name', $values, $errors)
            . $this->input('Bio', 'bio', $values, $errors)
            . '<button type=submit>Update profile</button></form></div>';

        return $this->layout('Profile', $main, true, $notice);
    }

    /**
     * @param list<string>|null $recovery codes to show once, right after enrolment
     * @param array<string,string> $errors
     */
    public function security(array $a, string $csrf, ?string $secretB32, array $errors, ?array $recovery, ?string $notice): string
    {
        if ($a['tf'] !== null) {
            $body = '<p>' . $this->msg('twofa_on') . '</p><p class=muted>Recovery codes left: ' . count($a['tf']['rc']) . '.</p>';
            if ($recovery !== null) {
                $body .= '<p>' . $this->msg('recovery_intro') . '</p><p class=mono>' . implode('<br>', array_map([self::class, 'e'], $recovery)) . '</p>';
            }
        } else {
            $label = $this->p->company . ':' . (string) $a['u'];
            $uri = 'otpauth://totp/' . rawurlencode($label) . '?secret=' . $secretB32 . '&issuer=' . rawurlencode($this->p->company);
            $body = '<p>Add this key to your authenticator app, then enter the six-digit code it shows.</p>'
                . '<p class=mono>' . self::e((string) $secretB32) . '</p><p class=mono>' . self::e($uri) . '</p>'
                . "<form method=post action='/settings/security'>" . self::csrf($csrf)
                . $this->input('Authentication code', 'otp', [], $errors, 'text', ' inputmode=numeric autocomplete=one-time-code')
                . '<button type=submit>Enable two-factor authentication</button></form>';
        }

        return $this->layout('Security', '<div class=card><h1>Two-factor authentication</h1>' . $body . '</div>', true, $notice);
    }

    /** @param array<string,string> $errors */
    public function confirm(string $csrf, bool $twoFactor, array $errors): string
    {
        $main = '<div class=card><h1>Verify it is you</h1><p class=muted>' . $this->msg('confirm_intro') . '</p>'
            . "<form method=post action='/settings/confirm'>" . self::csrf($csrf)
            . $this->input('Password', 'password', [], $errors, 'password', ' autocomplete=current-password')
            . ($twoFactor
                ? $this->input('Authentication code', 'otp', [], $errors, 'text', ' inputmode=numeric autocomplete=one-time-code')
                    . $this->input('Or a recovery code', 'recovery_code', [], $errors)
                : '')
            . '<button type=submit>Continue</button></form></div>';

        return $this->layout('Verify it is you', $main, true);
    }

    /**
     * @param list<array<string,mixed>> $tokens
     * @param array<string,string> $deleteCsrf token id => csrf
     */
    public function tokens(array $tokens, array $deleteCsrf, ?string $newToken, ?string $notice): string
    {
        $fresh = $newToken !== null
            ? '<div class=card><p>' . $this->msg('token_created') . '</p><p class=mono>' . self::e($newToken) . '</p></div>'
            : '';
        $rows = '';
        foreach ($tokens as $t) {
            $id = (string) $t['id'];
            $rows .= '<tr><td>' . self::e((string) $t['nt']) . ($t['k'] === 'oat' ? ' <span class=muted>(OAuth)</span>' : '') . '</td>'
                . '<td class=mono>' . self::e(implode(', ', $t['sc'])) . '</td>'
                . '<td>' . ((int) $t['x'] > 0 ? 'Expires ' . self::date((int) $t['x']) : 'No expiry') . '</td>'
                . '<td>' . ((int) $t['lu'] > 0 ? 'Last used ' . self::date((int) $t['lu']) : 'Never used') . '</td>'
                . "<td><form method=post action='/settings/tokens/" . self::e($id) . "/delete'>" . self::csrf($deleteCsrf[$id] ?? '')
                . '<button class=danger type=submit>Delete</button></form></td></tr>';
        }
        $main = $fresh . '<div class=card><div class=row><h1>Personal access tokens</h1></div>'
            . "<p><a href='/settings/tokens/new'>Create a token</a></p>"
            . ($rows === '' ? '<p class=muted>You have no tokens.</p>' : '<table>' . $rows . '</table>') . '</div>';

        return $this->layout('Personal access tokens', $main, true, $notice);
    }

    /**
     * @param array<string,string> $values
     * @param array<string,string> $errors
     * @param list<string> $checked
     * @param list<string> $offered
     */
    public function tokenNew(string $csrf, array $values, array $errors, array $checked, array $offered): string
    {
        $exp = $values['expiration'] ?? '30';
        $opts = '';
        foreach (['7' => '7 days', '30' => '30 days', '60' => '60 days', '90' => '90 days', 'none' => 'No expiration'] as $v => $label) {
            $opts .= "<option value='{$v}'" . ($exp === $v ? ' selected' : '') . '>' . $label . '</option>';
        }
        $scopes = '';
        foreach ($offered as $s) {
            $scopes .= "<label class=scope><input type=checkbox name='scopes[]' value='" . self::e($s) . "'"
                . (in_array($s, $checked, true) ? ' checked' : '') . '>' . self::e($s) . ' <span class=muted>'
                . self::e(ScopeSet::ALL[$s]) . '</span></label>';
        }
        $main = "<div class=card><h1>New personal access token</h1><form method=post action='/settings/tokens'>" . self::csrf($csrf)
            . $this->input('Note', 'note', $values, $errors)
            . "<label>Expiration<select name=expiration>{$opts}</select></label>" . $this->fieldError($errors, 'expiration')
            . '<h2>Scopes</h2>' . $scopes . $this->fieldError($errors, 'scopes')
            . '<button type=submit>Create token</button></form></div>';

        return $this->layout('New token', $main, true);
    }

    /** @param list<array<string,mixed>> $apps */
    public function apps(array $apps, ?string $notice): string
    {
        $rows = '';
        foreach ($apps as $a) {
            $rows .= "<tr><td><a href='/settings/applications/" . self::e((string) $a['id']) . "'>" . self::e((string) $a['nm']) . '</a></td>'
                . '<td class=mono>' . self::e((string) $a['ci']) . '</td></tr>';
        }
        $main = "<div class=card><h1>OAuth applications</h1><p><a href='/settings/applications/new'>Add an OAuth application</a></p>"
            . ($rows === '' ? '<p class=muted>No applications yet.</p>' : '<table>' . $rows . '</table>') . '</div>';

        return $this->layout('OAuth applications', $main, true, $notice);
    }

    /** @param array<string,string> $values @param array<string,string> $errors */
    public function appNew(string $csrf, array $values, array $errors): string
    {
        $main = "<div class=card><h1>New OAuth application</h1><form method=post action='/settings/applications'>" . self::csrf($csrf)
            . $this->input('Application name', 'name', $values, $errors)
            . $this->input('Homepage URL', 'homepage_url', $values, $errors, 'url')
            . $this->input('Callback URL', 'callback_url', $values, $errors, 'url')
            . $this->input('Description', 'description', $values, $errors)
            . '<button type=submit>Save application</button></form></div>';

        return $this->layout('New OAuth application', $main, true);
    }

    /** @param array<string,mixed> $app */
    public function appShow(array $app, string $csrfSecret, string $csrfDelete, ?string $newSecret, ?string $notice): string
    {
        $id = self::e((string) $app['id']);
        $secrets = '';
        foreach ($app['sx'] as $s) {
            $secrets .= '<li>Client secret created ' . self::date((int) $s[2]) . '</li>';
        }
        $main = ($newSecret !== null ? '<div class=card><p>' . $this->msg('secret_created') . '</p><p class=mono>' . self::e($newSecret) . '</p></div>' : '')
            . '<div class=card><h1>' . self::e((string) $app['nm']) . '</h1>'
            . '<p>Client ID</p><p class=mono>' . self::e((string) $app['ci']) . '</p>'
            . '<p class=muted>Homepage URL: <span class=mono>' . self::e((string) $app['hp']) . '</span></p>'
            . '<p class=muted>Callback URL: <span class=mono>' . self::e((string) $app['cb']) . '</span></p>'
            . ((string) $app['ds'] !== '' ? '<p class=muted>' . self::e((string) $app['ds']) . '</p>' : '')
            . '<h2>Client secrets</h2>' . ($secrets === '' ? '<p class=muted>No client secrets.</p>' : '<ul>' . $secrets . '</ul>')
            . "<form method=post action='/settings/applications/{$id}/secrets'>" . self::csrf($csrfSecret)
            . '<button type=submit>Create a client secret</button></form></div>'
            . '<div class=card><h2>Organization access</h2><p>' . $this->msg('approval_pending', ['company' => $this->p->company]) . '</p></div>'
            . "<div class=card><h2>Delete application</h2><form method=post action='/settings/applications/{$id}/delete'>" . self::csrf($csrfDelete)
            . '<button class=danger type=submit>Delete application</button></form></div>';

        return $this->layout((string) $app['nm'], $main, true, $notice);
    }

    /** @param list<string> $scopes */
    public function consent(string $appName, array $scopes, string $csrf, string $requestId): string
    {
        $list = '';
        foreach ($scopes as $s) {
            $list .= '<li><span class=mono>' . self::e($s) . '</span> ' . self::e(ScopeSet::ALL[$s]) . '</li>';
        }
        $main = '<div class=card><h1>Authorize ' . self::e($appName) . '</h1>'
            . '<p>' . self::e($appName) . ' is asking for access to your ' . self::e($this->p->company) . ' account.</p>'
            . ($list !== '' ? '<ul>' . $list . '</ul>' : '<p class=muted>Read-only access to your public profile.</p>')
            . "<form method=post action='/login/oauth/authorize'>" . self::csrf($csrf)
            . "<input type=hidden name=authorization_request value='" . self::e($requestId) . "'>"
            . "<div class=row><button type=submit name=authorize value=1>Authorize</button>"
            . "<button class=alt type=submit name=deny value=1>Cancel</button></div></form></div>";

        return $this->layout('Authorize application', $main, true);
    }

    public function code(string $appName, string $code, ?string $state): string
    {
        $main = '<div class=card><h1>Authorization code</h1><p>' . $this->msg('code_issued', ['app' => $appName]) . '</p>'
            . '<p class=mono>' . self::e($code) . '</p>'
            . ($state !== null ? '<p class=muted>State: <span class=mono>' . self::e($state) . '</span></p>' : '')
            . '</div>';

        return $this->layout('Authorization code', $main, true);
    }

    public function denied(string $appName): string
    {
        return $this->layout('Authorization denied', '<div class=card><h1>Authorization denied</h1><p>' . $this->msg('denied', ['app' => $appName]) . '</p></div>', true);
    }

    public function sso(string $csrf, string $requestId, bool $approval, ?string $appName): string
    {
        $c = self::e($this->p->company);
        $what = $approval && $appName !== null
            ? '<p>' . self::e($appName) . ' needs approval from an owner of ' . $c . ' before it can access organization data.</p>'
            : '<p>' . $this->msg('sso_intro', ['company' => $this->p->company]) . '</p>';
        $main = '<div class=card><h1>' . ($approval ? 'Request organization approval' : 'Single sign-on to ' . $c) . '</h1>' . $what
            . "<form method=post action='/orgs/" . self::e($this->p->slug) . "/sso'>" . self::csrf($csrf)
            . "<input type=hidden name=authorization_request value='" . self::e($requestId) . "'>"
            . '<button type=submit>' . ($approval ? 'Request approval' : 'Continue') . '</button></form></div>';

        return $this->layout('Single sign-on', $main, true);
    }

    public function approvalRequested(): string
    {
        return $this->layout('Approval requested', '<div class=card><h1>Approval requested</h1><p>' . $this->msg('approval_requested') . '</p></div>', true);
    }

    /** @param array<string,string> $values */
    public function idp(string $csrf, ?string $errorKey, array $values): string
    {
        $c = self::e($this->p->company);

        return '<!doctype html><html lang=en><head><meta charset=utf-8>'
            . "<meta name=viewport content='width=device-width,initial-scale=1'><title>Sign in · " . $c . ' Identity</title>'
            . '<style>' . self::css() . '.idp{max-width:360px;margin:4rem auto}</style></head><body><main class=idp><div class=card>'
            . '<h1>' . $c . ' Identity</h1>'
            . ($errorKey !== null ? '<p class=err>' . $this->msg($errorKey) . '</p>' : '')
            . "<form method=post action='/idp/" . self::e($this->p->slug) . "/signin'>" . self::csrf($csrf)
            . $this->input('Username or email', 'username', $values, [], 'text', ' autocomplete=username')
            . $this->input('Password', 'password', [], [], 'password', ' autocomplete=current-password')
            . '<button type=submit>Sign in</button></form></div></main></body></html>';
    }

    public function docs(bool $signedIn): string
    {
        $ops = [
            ['GET', 'user', 'Your profile', 'any token'],
            ['PATCH', 'user', 'Update your name and bio', 'user:write'],
            ['GET', 'user/orgs', 'Your organizations', 'read:org'],
            ['GET', 'user/orders', 'Your orders', 'orders:read'],
            ['GET', 'users', 'Organization members (single sign-on)', 'users:read'],
            ['GET', 'users/{login}', 'A member\'s public profile', 'any token'],
            ['GET', 'orgs/{org}', 'An organization', 'read:org'],
            ['GET', 'orgs/{org}/members', 'Organization members (single sign-on)', 'users:read'],
            ['GET', 'orders', 'Organization orders (single sign-on)', 'orders:read'],
            ['GET', 'orders/{id}', 'One order (single sign-on)', 'orders:read'],
            ['POST', 'orders/exports', 'Start an order export (single sign-on)', 'orders:export'],
            ['POST', 'auth/login', 'Exchange a username and password for a 15-minute token', 'none'],
        ];
        $rows = '';
        foreach ($ops as [$m, $path, $what, $scope]) {
            $rows .= '<tr><td class=mono>' . $m . '</td><td class=mono>/api/v2/' . self::e($path) . '<br>/v2/' . self::e($path) . '</td><td>'
                . self::e($what) . '</td><td class=mono>' . self::e($scope) . '</td></tr>';
        }
        $c = self::e($this->p->company);
        $main = '<div class=card><h1>' . $c . ' API</h1>'
            . '<p>Authenticate with a personal access token, an OAuth access token or a login token: '
            . '<span class=mono>Authorization: Bearer &lt;token&gt;</span> or <span class=mono>X-API-Key: &lt;token&gt;</span>. '
            . 'The <span class=mono>access_token</span> query parameter still works but is deprecated.</p>'
            . '<p>Every operation is served under both <span class=mono>/api/v2/</span> and <span class=mono>/v2/</span>. '
            . 'A machine-readable subset is at <span class=mono>/openapi.json</span>.</p>'
            . '<table><tr><th>Method</th><th>Path</th><th>Description</th><th>Scope</th></tr>' . $rows . '</table></div>'
            . '<div class=card><h2>Errors</h2><table>'
            . '<tr><td class=mono>401</td><td>Missing or invalid credentials.</td></tr>'
            . '<tr><td class=mono>403</td><td>The token lacks a scope, the resource requires single sign-on, or an OAuth application awaits owner approval. '
            . 'Single sign-on answers carry an <span class=mono>sso_url</span> and an <span class=mono>X-SSO</span> header.</td></tr>'
            . '<tr><td class=mono>404</td><td>The resource does not exist or is not visible to you.</td></tr>'
            . '<tr><td class=mono>429</td><td>Rate limited. Wait for <span class=mono>Retry-After</span> seconds. '
            . 'Limits are reported in <span class=mono>X-RateLimit-*</span> headers.</td></tr></table></div>';

        return $this->layout('API documentation', $main, $signedIn);
    }

    /** A form-level answer: an expired form, a save failure, a conflict, a throttle. */
    public function error(string $title, string $message, string $backHref, string $backLabel, bool $signedIn): string
    {
        $main = '<div class=card><h1>' . self::e($title) . '</h1><p class=err>' . self::e($message) . '</p>'
            . "<p><a href='" . self::e($backHref) . "'>" . self::e($backLabel) . '</a></p></div>';

        return $this->layout($title, $main, $signedIn);
    }

    public function notFound(bool $signedIn, string $messageKey = 'not_found'): string
    {
        return $this->layout('Not Found', '<div class=card><h1>Not Found</h1><p>' . $this->msg($messageKey) . "</p><p><a href='/'>Go home</a></p></div>", $signedIn);
    }

    public function methodNotAllowed(bool $signedIn): string
    {
        return $this->layout('Method Not Allowed', '<div class=card><h1>Method Not Allowed</h1></div>', $signedIn);
    }
}
