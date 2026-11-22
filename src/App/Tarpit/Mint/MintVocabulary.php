<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use LogicException;

/**
 * Every message the account surface shows, in one closed table. Placeholders are filled only from
 * persona values, closed-set names or numbers the code computes; a request byte is never a filler.
 * A message left with an unfilled placeholder is a bug and throws, so it can never reach a client.
 */
final class MintVocabulary
{
    public const MESSAGES = [
        // form-level answers
        'csrf' => 'This form has expired. Reload the page and try again.',
        'session_expired' => 'Your session has expired. Please sign in again.',
        'throttled' => "You've made too many requests. Try again in {wait}.",
        'edit_conflict' => 'Your account changed while you were editing. Review and resubmit.',
        'transient' => "We couldn't save your changes. Please try again.",
        'signin_failed' => 'Something went wrong. Please try again.',
        'signin_wrong' => 'Incorrect username or password.',
        'body_too_large' => 'The request is too large.',
        'method' => 'Method Not Allowed',
        'not_found' => 'Not Found',
        // sign-up
        'username_invalid' => 'Username may only contain letters, numbers, dots, dashes and underscores, and must be 2 to 39 characters.',
        'username_taken' => 'Username is already taken.',
        'email_invalid' => 'Email is invalid.',
        'email_taken' => 'Email is already in use.',
        'password_length' => 'Password must be 8 to 72 characters.',
        'password_mismatch' => "Password confirmation doesn't match.",
        // personal access tokens
        'note_blank' => "Note can't be blank.",
        'note_long' => 'Note is too long (maximum is 100 characters).',
        'note_charset' => 'Note may only contain letters, numbers, spaces and . _ : @ + = , / -',
        'note_taken' => 'Note has already been taken.',
        'scopes_none' => 'Select at least one scope.',
        'scopes_unknown' => 'Select scopes from the list.',
        'expiration_bad' => 'Choose an expiration.',
        'expiration_none' => '{company} requires personal access tokens to expire within 90 days.',
        'scope_owner' => 'Only organization owners can grant admin:org.',
        'scope_2fa' => 'Enable two-factor authentication to grant users:read, orders:read or orders:export.',
        'token_limit' => 'You can have at most 8 active tokens. Delete one before creating another.',
        'token_created' => "Make sure to copy your personal access token now. You won't be able to see it again.",
        'token_deleted' => 'Token deleted.',
        // OAuth applications
        'app_name_blank' => "Application name can't be blank.",
        'app_name_long' => 'Application name is too long (maximum is 100 characters).',
        'app_name_charset' => 'Application name may only contain letters, numbers, spaces and . _ : @ + = , / -',
        'app_name_taken' => 'Application name has already been taken.',
        'homepage_invalid' => 'Homepage URL is invalid.',
        'callback_invalid' => 'Callback URL is invalid.',
        'description_long' => 'Description is too long (maximum is 200 characters).',
        'description_charset' => 'Description may only contain letters, numbers, spaces and . _ : @ + = , / -',
        'app_limit' => 'You can register up to 3 applications.',
        'app_created' => 'Application registered.',
        'app_deleted' => 'Application deleted.',
        'secret_created' => "Make sure to copy your new client secret now. You won't be able to see it again.",
        'approval_pending' => 'Organization access to {company}: approval required.',
        // profile, security, confirm
        'profile_saved' => 'Profile updated.',
        'name_long' => 'Name is too long (maximum is 160 characters).',
        'name_charset' => 'Name may only contain letters, numbers, spaces and . _ : @ + = , / -',
        'bio_long' => 'Bio is too long (maximum is 160 characters).',
        'bio_charset' => 'Bio may only contain letters, numbers, spaces and . _ : @ + = , / -',
        'otp_invalid' => 'Two-factor code is invalid.',
        'twofa_on' => 'Two-factor authentication is on.',
        'twofa_enabled' => 'Two-factor authentication is now on.',
        'recovery_intro' => 'Save these recovery codes somewhere safe. Each code can be used once if you lose access to your authenticator app.',
        'confirm_password' => 'Incorrect password.',
        'confirm_second' => 'Enter a valid two-factor code or recovery code.',
        'confirm_intro' => 'Confirm access to continue. You will not be asked again for a few minutes.',
        // OAuth authorization
        'app_not_found' => 'Application not found.',
        'redirect_mismatch' => 'The redirect URI does not match this application.',
        'code_issued' => 'Authorization code for {app}. Return to {app} and enter it. It expires in 10 minutes.',
        'denied' => 'You denied {app} access to your account.',
        // single sign-on and the identity provider
        'sso_intro' => '{company} requires single sign-on to access its resources.',
        'idp_unassigned' => "Your account isn't assigned to this application. Contact your administrator.",
        'idp_invalid' => 'Invalid username or password',
        'idp_locked' => 'Too many sign-in attempts. Try again in 15 minutes.',
        'approval_requested' => 'Approval requested. An organization owner will review your request.',
        // the API
        'api_auth' => 'Requires authentication',
        'api_bad_credentials' => 'Bad credentials',
        'api_scope' => 'This token does not have the {scope} scope.',
        'api_sso' => '{company} requires single sign-on for this resource. Authorize this token for the organization to continue.',
        'api_approval' => 'An owner must approve {app} before it can access {company} data.',
        'api_member_sso' => 'This account signs in through {company} SSO.',
        'api_login_fields' => 'Username and password are required.',
        'api_invalid_body' => 'Problems parsing JSON',
        'api_secondary' => 'You have exceeded a secondary rate limit. Please wait a few minutes before you try again.',
        'api_retry' => 'Please retry later.',
        // the token endpoint
        'oauth_invalid_request' => 'The request is missing a required parameter.',
        'oauth_invalid_client' => 'Client authentication failed.',
        'oauth_invalid_grant' => 'The authorization grant is invalid, expired or already used.',
        'oauth_unauthorized_client' => 'This client may not use that grant type.',
        'oauth_unsupported_grant_type' => 'That grant type is not supported.',
        'oauth_invalid_scope' => 'The requested scope is wider than the grant.',
    ];

    /** @param array<string,string|int> $vars */
    public static function text(string $key, array $vars = []): string
    {
        if (!isset(self::MESSAGES[$key])) {
            throw new LogicException('unknown message');
        }
        $pairs = [];
        foreach ($vars as $k => $v) {
            $pairs['{' . $k . '}'] = (string) $v;
        }
        $out = strtr(self::MESSAGES[$key], $pairs);
        if (preg_match('/\{[a-z_]+\}/', $out) === 1) {
            throw new LogicException('unfilled placeholder');
        }

        return $out;
    }

    /** "1 minute" or "N minutes" for a wait in seconds, rounded up. */
    public static function wait(int $seconds): string
    {
        $m = max(1, intdiv($seconds + 59, 60));

        return $m === 1 ? '1 minute' : $m . ' minutes';
    }

    /** @return list<string> the placeholder names a message takes */
    public static function placeholders(string $key): array
    {
        preg_match_all('/\{([a-z_]+)\}/', self::MESSAGES[$key] ?? '', $m);

        return array_values(array_unique($m[1]));
    }
}
