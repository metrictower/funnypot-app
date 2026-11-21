<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * One console turn, decided before the engine answers (so the sleep decoy knows whether the command
 * "ran") and served after it (once the winning rule confirms the shell owns the request).
 */
final class ShellTurn
{
    /** Set by AdaptiveShell::serve() when the shell actually replaced the response. */
    public bool $served = false;
    /** 'A' (console path) or 'B' (any path whose answer was a shell/cmdi/LFI rule). */
    public ?string $consoleRule = null;
    /** The core rule the shell replaced, for the attribution log. */
    public string $coreRule = '';

    public function __construct(
        public readonly string $ip,
        public readonly string $path,
        public readonly FootholdIdentity $identity,
        public readonly string $valueSource,
        public readonly bool $pathInConsole,
        public readonly bool $landingOnly,
        public readonly bool $executes,
        public readonly ?int $sleepSeconds,
        public readonly string $output,
        public readonly ?Outcome $outcome,
        public readonly bool $simple,
        public readonly SourceState $stateAfter,
    ) {
    }

    /** @return array<string,scalar|null> the attribution row for this turn */
    public function row(int $delayMs): array
    {
        return [
            'identity' => $this->identity->name,
            'value_source' => $this->valueSource,
            'simple' => $this->simple ? 1 : 0,
            'kind' => $this->outcome === null ? 'landing' : $this->outcome->kind,
            'sub' => $this->landingOnly ? 'landing' : ($this->outcome->sub ?? ''),
            'family' => $this->outcome?->family ?? '',
            'msg_id' => $this->outcome?->msgId ?? '',
            'owned_by_rule' => $this->coreRule,
            'console_rule' => $this->consoleRule ?? '',
            'delay_ms' => $delayMs,
        ];
    }
}
