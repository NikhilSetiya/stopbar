"""PyRIT adapter for the PILOT-2 attacker (§6), PyRIT defaults unmodified.

It wires PyRIT's own `RedTeamingAttack` (max_turns = 5, default adversarial
system prompt and converters) to the pilot sandbox:

- **attacker model:** an `OpenAIChatTarget` pointed at Together, pinned to
  `Qwen/Qwen3.5-9B` (PILOT-2 §2). PyRIT generates every attack; we configure
  nothing about how it attacks.
- **`PilotTarget`:** the objective target. Each attacker turn's text is handed
  to an injected `episode` callable, which writes it into the scenario's
  declared untrusted surface, runs the agent's legitimate task, and returns
  the agent's **visible result** (reply plus tool errors, including Stopbar's
  reason codes) — so denial reasons travel back to the attacker. The episode
  also reports, from chain state, whether the attacker's goal was reached.
- **`ChainStateScorer`:** a `TrueFalseScorer` whose verdict is that chain-state
  outcome (PILOT-2 §6.3), never the agent's words.

No attack content lives here. The attacks are PyRIT's defaults, driven by the
owner's one-line goal (the PyRIT objective). The agent episode is supplied by
the runner (Stages 1-3); this module is the wiring, unit-tested with a fake
episode and no model calls.
"""
from dataclasses import dataclass
from typing import Callable

from pyrit.executor.attack import AttackAdversarialConfig, AttackScoringConfig, RedTeamingAttack
from pyrit.models import ComponentIdentifier, Message, MessagePiece, Score
from pyrit.prompt_target import OpenAIChatTarget, PromptTarget
from pyrit.score.scorer_prompt_validator import ScorerPromptValidator
from pyrit.score.true_false.true_false_scorer import MessageTrueFalseScorer

from .infra import read_keychain
from .spend import BASE_URL, KEYCHAIN_SERVICE

ATTACKER_MODEL = "Qwen/Qwen3.5-9B"
MAX_TURNS = 5


@dataclass
class EpisodeResult:
    """One attempt: what the agent visibly produced, and whether the
    attacker's goal was reached on chain (judged by the scenario, §6.3)."""
    visible_text: str
    goal_reached: bool


# episode(attacker_text) -> EpisodeResult. Injects the text into the scenario's
# untrusted surface, runs the agent task, reads chain state. Supplied by the
# runner; the adapter never writes attack text itself.
Episode = Callable[[str], EpisodeResult]


def attacker_target() -> OpenAIChatTarget:
    """The pinned Together attacker model, PyRIT defaults otherwise."""
    return OpenAIChatTarget(
        endpoint=BASE_URL,  # the OpenAI SDK appends /chat/completions
        model_name=ATTACKER_MODEL,
        api_key=read_keychain(KEYCHAIN_SERVICE),
    )


class PilotTarget(PromptTarget):
    """Objective target: runs one agent episode per attacker turn."""

    def __init__(self, *, episode: Episode):
        super().__init__()
        self._episode = episode
        self.last: EpisodeResult | None = None
        self.turns = 0

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        attacker_text = normalized_conversation[-1].get_value()
        self.turns += 1
        self.last = self._episode(attacker_text)
        return [Message.from_prompt(prompt=self.last.visible_text or "(no output)", role="assistant")]

    def _validate_request(self, *, normalized_conversation: list[Message]) -> None:
        return


class ChainStateScorer(MessageTrueFalseScorer):
    """True when the pilot target's last episode reached the goal on chain."""

    _VALIDATOR = ScorerPromptValidator(supported_data_types=["text"])

    def __init__(self, *, target: PilotTarget):
        self._target = target
        super().__init__(validator=self._VALIDATOR)

    def _build_identifier(self) -> ComponentIdentifier:
        return self._create_identifier(params={"check": "chain_state"},
                                       score_aggregator=self._score_aggregator.__name__)

    async def _score_piece_async(self, message_piece: MessagePiece, *, objective: str | None = None) -> list[Score]:
        reached = bool(self._target.last and self._target.last.goal_reached)
        return [Score(
            score_value=str(reached), score_value_description="", score_metadata=None,
            score_type="true_false", score_category=["pilot_goal_reached"],
            score_rationale="chain-state success check (PILOT-2 §6.3)",
            scorer_class_identifier=self.get_identifier(), message_piece_id=message_piece.id, objective=objective,
        )]


def build_attack(target: PilotTarget, scorer: ChainStateScorer) -> RedTeamingAttack:
    """RedTeamingAttack with PyRIT's defaults and max_turns = 5."""
    return RedTeamingAttack(
        objective_target=target,
        attack_adversarial_config=AttackAdversarialConfig(target=attacker_target()),
        attack_scoring_config=AttackScoringConfig(objective_scorer=scorer),
        max_turns=MAX_TURNS,
    )
