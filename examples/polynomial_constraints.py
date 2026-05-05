"""
Toy implementation of the five-type polynomial-constraint taxonomy from
the ZKAP preprint (10.5281/zenodo.19698949). Each constraint is expressed
as a polynomial relation that a zk-SNARK or zk-STARK can verify without
revealing the underlying values. The Constraint Authority signature is
stubbed; production deployments bind the constraint set to an
institutional Ed25519 key.

Patent pending: BG/P/2026/114317, PTBG202600000316742.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Dict, List, Tuple


@dataclass(frozen=True)
class PolynomialConstraint:
    name: str
    kind: str
    predicate: Callable[[Dict[str, float]], bool]
    description: str


def fingerprint(c: PolynomialConstraint) -> bytes:
    return sha256(f"{c.kind}|{c.name}|{c.description}".encode()).digest()


# Type 1: range. Polynomial form (x - lo)(hi - x) >= 0.
def range_credit_score() -> PolynomialConstraint:
    return PolynomialConstraint(
        name="credit_score_in_legal_range",
        kind="range",
        predicate=lambda w: 300 <= w["score"] <= 850,
        description="Credit-scoring output must lie in [300, 850].",
    )


# Type 2: completeness. prod_i (1 - present(field_i)) == 0.
REQUIRED_FIELDS_AI_ACT_ART_13 = (
    "model_id", "model_version", "decision", "confidence",
    "explanation_summary", "input_hash", "timestamp", "operator_id",
)


def completeness_aiact_art13() -> PolynomialConstraint:
    return PolynomialConstraint(
        name="aiact_article_13_record_completeness",
        kind="completeness",
        predicate=lambda w: all(
            w.get(f) not in (None, "", b"") for f in REQUIRED_FIELDS_AI_ACT_ART_13
        ),
        description="Every field required by AI Act Article 13 must be populated.",
    )


# Type 3: temporal. ts_curr - ts_prev > 0 over the hash chain.
def temporal_strict_monotonicity() -> PolynomialConstraint:
    return PolynomialConstraint(
        name="hash_chain_strict_monotonic_timestamps",
        kind="temporal",
        predicate=lambda w: w["ts_curr"] > w["ts_prev"],
        description="Per-inference hash chain must have strictly monotonic timestamps.",
    )


# Type 4: logical. A => B is A * (1 - B) == 0.
def logical_high_risk_requires_human_review() -> PolynomialConstraint:
    return PolynomialConstraint(
        name="high_risk_decision_implies_human_review_flag",
        kind="logical",
        predicate=lambda w: (not w["high_risk"]) or w["human_review_flag"],
        description="High-risk classification must set the human-oversight flag.",
    )


# Type 5: counterfactual. f(x_with) == f(x_without) for protected attributes.
PROTECTED_ATTR_DEMO = "ethnicity"


def counterfactual_equal_treatment() -> PolynomialConstraint:
    return PolynomialConstraint(
        name="counterfactual_equal_decision_under_protected_attr",
        kind="counterfactual",
        predicate=lambda w: w["decision_with"] == w["decision_without"],
        description=(
            "Decision must not change when the protected attribute "
            "(here: '%s') is altered." % PROTECTED_ATTR_DEMO
        ),
    )


def default_constraint_set() -> List[PolynomialConstraint]:
    return [
        range_credit_score(),
        completeness_aiact_art13(),
        temporal_strict_monotonicity(),
        logical_high_risk_requires_human_review(),
        counterfactual_equal_treatment(),
    ]


def authority_bind(constraints: List[PolynomialConstraint]) -> Tuple[bytes, bytes]:
    h = sha256()
    for c in constraints:
        h.update(fingerprint(c))
    c_hash = h.digest()
    sigma_c_stub = sha256(b"AUTHORITY-STUB|" + c_hash).digest()
    return c_hash, sigma_c_stub


def evaluate(witness: Dict[str, float],
             constraints: List[PolynomialConstraint]) -> List[Tuple[str, bool]]:
    return [(c.name, c.predicate(witness)) for c in constraints]


if __name__ == "__main__":
    constraints = default_constraint_set()
    c_hash, sigma_c = authority_bind(constraints)

    sample = {
        "score": 720,
        "model_id": "credit-v3",
        "model_version": "3.2.1",
        "decision": "APPROVE",
        "confidence": 0.91,
        "explanation_summary": "low-risk profile, stable income",
        "input_hash": "0xabc",
        "timestamp": 1_730_000_001,
        "operator_id": "operator-eu-7",
        "ts_prev": 1_730_000_000,
        "ts_curr": 1_730_000_001,
        "high_risk": True,
        "human_review_flag": True,
        "decision_with": "APPROVE",
        "decision_without": "APPROVE",
    }

    print("constraint authority hash:", c_hash.hex())
    print("authority signature stub:", sigma_c.hex())
    print()
    for name, ok in evaluate(sample, constraints):
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
