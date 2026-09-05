<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\AssistantTurn;
use Funnypot\App\AiApi\Value\ToolCall;
use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\App\AiApi\Value\ToolDefinition;

/**
 * Decides whether a chat turn should be a fabricated tool call, a length stop, or nothing (fall through
 * to the ordinary text path). It combines the closed {@see SafeToolSelector}/{@see SafeArgumentSynthesizer},
 * the request-authoritative loop count, the output budget and the atomic {@see AiToolStateStore}. It
 * never executes anything, never touches the sidecar, and never reflects a returned result — a consumed
 * result converges to a fixed acknowledgement that names nothing from the client's payload.
 */
final class ToolTurnPlanner
{
    /** Absolute ceiling on fabricated calls per conversation — not operator-raisable (spec §5). */
    public const HARD_CEILING = 4;

    public function __construct(
        private SafeToolSelector $selector,
        private SafeArgumentSynthesizer $synth,
        private UsageEstimator $usage
    ) {
    }

    /**
     * @param string $callId provider-shaped id for a fabricated call ('' for Ollama, which has none)
     * @param string $actor  opaque per-source digest for state scoping
     * @param int    $limit  effective per-conversation call limit (already clamped to 0..HARD_CEILING)
     * @return AssistantTurn|null a tool_call/length/text turn, or null to fall through to the text path
     */
    public function plan(ChatRequest $req, string $callId, string $actor, ?AiToolStateStore $store, int $limit): ?AssistantTurn
    {
        if ($req->tools === []) {
            return null;
        }
        $choice = new ToolChoice($req->toolChoiceMode, $req->toolChoiceName);

        // A returned tool result: corroborate a single consume, then converge (or emit one more call only
        // when the new user turn explicitly asks for another and we are still under the cap).
        if ($req->hasToolResult) {
            $advance = true;
            if ($store !== null) {
                $outcome = $store->consume($this->consumeCorrelator($req, $actor));
                $advance = $outcome === AiToolStateStore::CONSUMED;
            }
            if ($advance && $req->wantsAnotherCall && $req->priorToolCalls < $limit) {
                $turn = $this->buildCall($req, $choice, $callId, $actor, $store, $limit);
                if ($turn !== null) {
                    return $turn;
                }
            }

            return AssistantTurn::text($this->ackText($req));
        }

        // Fresh decision. At/over the cap we converge to the ordinary text path.
        if ($req->priorToolCalls >= $limit) {
            return null;
        }

        return $this->buildCall($req, $choice, $callId, $actor, $store, $limit);
    }

    /**
     * Select + synthesise a single inert call, subject to budget. Returns a tool_call or length turn, a
     * clarification when the client forced a call but nothing is safe, or null to fall through.
     */
    private function buildCall(ChatRequest $req, ToolChoice $choice, string $callId, string $actor, ?AiToolStateStore $store, int $limit): ?AssistantTurn
    {
        $tool = $this->selector->select($req->tools, $choice, $req->callIntent);
        if ($tool === null) {
            return $choice->forcesCall() ? AssistantTurn::text($this->clarificationText($req)) : null;
        }

        $syn = $this->synth->synthesize($tool);
        if ($syn === null) {
            return $choice->forcesCall() ? AssistantTurn::text($this->clarificationText($req)) : null;
        }
        [$args, $json] = $syn;
        $call = new ToolCall($callId, $tool->name, $args, $json);
        $turn = AssistantTurn::toolCall($call);

        // Budget fit: a too-small max_tokens yields a structural length stop, never a partial call.
        if ($req->maxOutputTokens >= 0 && $this->usage->outputTokens($turn) > $req->maxOutputTokens) {
            return AssistantTurn::length();
        }

        if ($store !== null) {
            // Best-effort: a full/locked store still serves the call statelessly.
            $store->issue(
                $this->scope($req, $actor),
                $this->issueCorrelator($req, $actor, $callId, $tool),
                $req->dialect,
                $req->priorToolCalls
            );
        }

        return $turn;
    }

    private function scope(ChatRequest $req, string $actor): string
    {
        return hash('sha256', $actor . '|' . $req->dialect . '|' . $req->conversationKey);
    }

    private function issueCorrelator(ChatRequest $req, string $actor, string $callId, ToolDefinition $tool): string
    {
        $base = $req->dialect === 'ollama-chat'
            ? 'conv:' . $req->conversationKey . ':' . $tool->name
            : 'id:' . $callId;

        return hash('sha256', $actor . '|' . $req->dialect . '|' . $base);
    }

    private function consumeCorrelator(ChatRequest $req, string $actor): string
    {
        $base = $req->dialect === 'ollama-chat'
            ? 'conv:' . $req->conversationKey . ':' . (string) $req->lastToolName
            : 'id:' . (string) $req->lastCallId;

        return hash('sha256', $actor . '|' . $req->dialect . '|' . $base);
    }

    /** A fixed post-result completion that references nothing from the client's payload. */
    private function ackText(ChatRequest $req): string
    {
        $lines = [
            'Thanks — I went through those results. Everything looks consistent; nothing there needs changing.',
            'Reviewed the output. It all checks out, so no further action is needed on my end.',
            'Got it — I read through what came back and it lines up with what I expected.',
        ];

        return $lines[abs(crc32($req->conversationKey . $req->userText)) % count($lines)];
    }

    /** A provider-neutral refusal that never names the honeypot or its safety policy. */
    private function clarificationText(ChatRequest $req): string
    {
        return "I can't complete that with the tools provided. Could you clarify what you'd like me to look up?";
    }
}
