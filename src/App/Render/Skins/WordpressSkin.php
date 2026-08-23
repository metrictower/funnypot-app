<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Skins;

use Funnypot\App\Render\AbstractSkin;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\PathSegments;
use Funnypot\App\Render\VisualPersona;

/**
 * A hand-authored lookalike of the wp-login.php screen — not a copy of WordPress markup, just close
 * enough in shape (centered card, a `login`-classed form, `log`/`pwd` fields) that the fake page reads
 * as "one more WP install" among the millions of real ones. The WP-shaped class names below are fixed
 * literals on purpose: for this skin, blending into the WP install-base fleet-wide *is* the anti-
 * fingerprint property, unlike GenericSkin where seed-derived CSS avoids a shared hash.
 */
final class WordpressSkin extends AbstractSkin
{
    public function matches(string $path): bool
    {
        // "wp-" is a segment PREFIX, not a whole segment on its own — the real files it needs to
        // catch (wp-login.php, wp-admin, wp-content, wp-json, ...) all carry more than the bare token.
        return PathSegments::hasPrefixed($path, 'wp-');
    }

    public function key(): string
    {
        return 'wordpress';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath): string
    {
        $siteRaw = $slots->appName() !== '' ? $slots->appName() : $persona->company();
        $site = $this->esc($siteRaw);
        $domain = $this->esc($persona->domain());

        $html = '<div id="login">';
        $html .= '<h1><a href="#">' . $site . '</a></h1>';

        $notice = $slots->heading() !== '' ? $slots->heading() : $slots->flash();
        if ($notice !== '') {
            $html .= '<div id="login_error">' . $this->esc($notice) . '</div>';
        }
        if ($slots->intro() !== '') {
            $html .= '<p class="message">' . $this->esc($slots->intro()) . '</p>';
        }

        // action is the pre-escaped request path; hrefs below are trusted literals, never model bytes.
        $html .= '<form name="loginform" id="loginform" class="login" action="' . $escapedPath . '" method="post">'
            . '<p class="login-username">'
            . '<label for="user_login">Username or Email Address</label>'
            . '<input type="text" name="log" id="user_login" class="input" size="20" autocapitalize="off">'
            . '</p>'
            . '<p class="login-password">'
            . '<label for="user_pass">Password</label>'
            . '<input type="password" name="pwd" id="user_pass" class="input" size="20">'
            . '</p>'
            . '<p class="forgetmenot">'
            . '<label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label>'
            . '</p>'
            . '<p class="submit">'
            . '<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">'
            . '</p>'
            . '</form>';

        $html .= '<p id="nav"><a href="#">Lost your password?</a></p>';
        $html .= '</div>';

        $html .= '<p class="footer">' . $domain;
        if ($slots->footerNote() !== '') {
            $html .= ' &middot; ' . $this->esc($slots->footerNote());
        }
        $html .= '</p>';

        return $this->document(
            $siteRaw . ' - Log In',
            $this->css(),
            $html,
            ' lang="en-US"',
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width">',
            ' class="login no-js"'
        );
    }

    private function css(): string
    {
        // Palette reads as a WP-style admin scheme (blue primary, red error, blue-grey neutrals) but
        // every hex is nudged off WordPress's exact default color-scheme tokens — resemblance, not reuse.
        return 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
            . 'background:#eeeff0;font-family:sans-serif;color:#393f47}'
            . '#login{width:320px;padding:26px 24px;background:#fff;border:1px solid #d8d9db;border-radius:4px;'
            . 'box-shadow:0 1px 3px rgba(0,0,0,.08)}'
            . '#login h1{text-align:center;margin:0 0 20px}'
            . '#login h1 a{color:#393f47;text-decoration:none;font-size:1.3em}'
            . '#login_error{background:#faeff0;border-left:4px solid #d1393c;padding:10px 12px;margin-bottom:16px}'
            . '.message{background:#eef4fa;border-left:4px solid #6ba7e0;padding:10px 12px;margin-bottom:16px}'
            . '.login-username,.login-password{margin-bottom:14px}'
            . '#login label{display:block;margin-bottom:4px;font-size:.9em}'
            . '#login .input{width:100%;box-sizing:border-box;padding:6px 8px;border:1px solid #888b91;border-radius:3px}'
            . '.forgetmenot label{display:flex;align-items:center;gap:6px;font-size:.9em}'
            . '.button-primary{background:#1f6caa;color:#fff;border:1px solid #1f6caa;border-radius:3px;'
            . 'padding:8px 14px;cursor:pointer}'
            . '#nav{text-align:center;margin-top:14px;font-size:.9em}'
            . '#nav a{color:#1f6caa;text-decoration:none}'
            . '.footer{text-align:center;margin-top:16px;color:#60656c;font-size:.85em}';
    }
}
