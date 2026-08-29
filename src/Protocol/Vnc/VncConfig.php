<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Vnc;

/**
 * Configuration for the VNC honeypot service.
 * Supports:
 * - Realistic desktop background image (eth.png — a fake ETH staking wallet)
 * - Taunt mode: a click shows a fake "Reverse VNC connection?" dialog, then a scripted slideshow
 *   (ah-ah-ah -> "Reversing VNC connection" -> evil-troll), then a burst of malformed RFB and a
 *   disconnect. Idle (pre-interaction) connections are held open for idleTimeoutSec.
 */
final class VncConfig
{
    public function __construct(
        public string $style = 'realistic', // 'realistic' | 'taunt'
        public ?string $image = null,
        public int $width = 1920,
        public int $height = 1080,
        public string $clipboard = 'i am a naughty script kiddie and i got hacked',
        public float $clipboardInterval = 0.0,
        public bool $beep = false,
        public float $beepInterval = 1.0,
        public string $cursor = 'normal', // 'normal' | 'troll' | 'invisible'
        public bool $chaosResize = false,
        public bool $chaosResizeOnAction = true,
        public int $massiveWidth = 8192,
        public int $massiveHeight = 8192,
        public string $serverName = 'Remote Server Desktop',
        public string $authMode = 'none',
        public float $tauntPopupSec = 2.0,
        public bool $dodgePopup = true,
        public bool $malformedExit = true,
        public float $idleTimeoutSec = 900.0
    ) {
    }

    public static function fromEnv(): self
    {
        // Service-specific style wins over the global one: deployments always set FUNNYPOT_STYLE
        // (Docker bakes a default), so FUNNYPOT_VNC_STYLE must take precedence to mean anything.
        $styleEnv = getenv('FUNNYPOT_VNC_STYLE') ?: getenv('FUNNYPOT_STYLE');
        $style = ($styleEnv && strtolower($styleEnv) === 'taunt') ? 'taunt' : 'realistic';
        $isTaunt = ($style === 'taunt');

        // Look for the bundled desktop screenshot (eth.png)
        $imageEnv = getenv('FUNNYPOT_VNC_IMAGE');
        $image = null;
        $candidatePaths = [
            $imageEnv ?: '',
            dirname(__DIR__, 3) . '/demo/assets/eth.png'
        ];
        foreach ($candidatePaths as $path) {
            if ($path !== '' && is_file($path)) {
                $image = $path;
                break;
            }
        }

        $defaultW = 800;
        $defaultH = 600;
        if ($image !== null) {
            $imgSize = @getimagesize($image);
            if ($imgSize !== false) {
                $defaultW = (int) $imgSize[0];
                $defaultH = (int) $imgSize[1];
            }
        }

        $wEnv = getenv('FUNNYPOT_VNC_WIDTH');
        $hEnv = getenv('FUNNYPOT_VNC_HEIGHT');
        $width = $wEnv !== false && is_numeric($wEnv) ? (int) $wEnv : $defaultW;
        $height = $hEnv !== false && is_numeric($hEnv) ? (int) $hEnv : $defaultH;

        $clipboardDefault = $isTaunt
            ? 'say "i am a naughty script kiddie and i got hacked" && sudo reboot 0'
            : "C:\\WINDOWS\\SYSTEM\\HACKER.LOG: Intruder logged from {ip}. System will be locked.";
        $clipboard = getenv('FUNNYPOT_VNC_CLIPBOARD') ?: $clipboardDefault;
        $cbInterval = (float) (getenv('FUNNYPOT_VNC_CLIPBOARD_INTERVAL') ?: '0');

        $beepEnv = getenv('FUNNYPOT_VNC_BEEP');
        $beep = ($beepEnv !== false) ? filter_var($beepEnv, FILTER_VALIDATE_BOOLEAN) : $isTaunt;
        $beepInterval = max(0.2, (float) (getenv('FUNNYPOT_VNC_BEEP_INTERVAL') ?: '0.5'));

        $cursorDefault = 'normal';
        $cursor = strtolower(getenv('FUNNYPOT_VNC_CURSOR') ?: $cursorDefault);

        $chaosResizeEnv = getenv('FUNNYPOT_VNC_CHAOS_RESIZE');
        $chaosResize = ($chaosResizeEnv !== false) ? filter_var($chaosResizeEnv, FILTER_VALIDATE_BOOLEAN) : false;

        $actionRaw = getenv('FUNNYPOT_VNC_CHAOS_RESIZE_ON_ACTION');
        $chaosResizeOnAction = ($actionRaw === false) ? true : filter_var($actionRaw, FILTER_VALIDATE_BOOLEAN);

        $massiveWidth = (int) (getenv('FUNNYPOT_VNC_MASSIVE_WIDTH') ?: '8192');
        $massiveHeight = (int) (getenv('FUNNYPOT_VNC_MASSIVE_HEIGHT') ?: '8192');

        // The bundled desktop is a fake ETH staking wallet; the RFB name matches that persona.
        $serverName = getenv('FUNNYPOT_VNC_NAME') ?: ($image ? 'ETH staking SRV02' : 'Windows 95 Workstation');
        $authMode = strtolower(getenv('FUNNYPOT_VNC_AUTH') ?: 'none');

        // A click first shows a fake "Reverse VNC connection?" dialog for this long, then the
        // real storm begins.
        $tauntPopupSec = max(0.0, (float) (getenv('FUNNYPOT_VNC_POPUP_DELAY') ?: '2'));

        // The fake dialog jumps away from the pointer so it can never be clicked. On by default.
        $dodgeRaw = getenv('FUNNYPOT_VNC_DODGE_POPUP');
        $dodgePopup = ($dodgeRaw === false) ? true : filter_var($dodgeRaw, FILTER_VALIDATE_BOOLEAN);

        // Just before dropping the client, spray a burst of invalid RFB to confuse its viewer. On
        // by default; only ever sent to an attacker who tripped the taunt, never on the honest path.
        $malformedRaw = getenv('FUNNYPOT_VNC_MALFORMED_EXIT');
        $malformedExit = ($malformedRaw === false) ? true : filter_var($malformedRaw, FILTER_VALIDATE_BOOLEAN);

        // VNC-only idle timeout: a lurking bot may sit silently for minutes to see if the box is in
        // use, so hold the connection open far longer than the other protocols before dropping it.
        $idleTimeoutSec = max(1.0, (float) (getenv('FUNNYPOT_VNC_IDLE_TIMEOUT') ?: '900'));

        return new self(
            style: $style,
            image: $image,
            width: $width,
            height: $height,
            clipboard: $clipboard,
            clipboardInterval: $cbInterval,
            beep: $beep,
            beepInterval: $beepInterval,
            cursor: $cursor,
            chaosResize: $chaosResize,
            chaosResizeOnAction: $chaosResizeOnAction,
            massiveWidth: $massiveWidth,
            massiveHeight: $massiveHeight,
            serverName: $serverName,
            authMode: $authMode,
            tauntPopupSec: $tauntPopupSec,
            dodgePopup: $dodgePopup,
            malformedExit: $malformedExit,
            idleTimeoutSec: $idleTimeoutSec
        );
    }
}
