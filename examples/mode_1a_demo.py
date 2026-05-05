"""
Mode 1A relaxes the strict prove-before-output rule to commit-before-
release for workloads with hard real-time constraints. The output is
released immediately under a PENDING tag, the proof is generated in
parallel, and the chain entry is updated to VERIFIED or
CONSTRAINT_VIOLATED once the verifier has run. The transparency-log
anchor makes the original commitment binding even if the proof later
fails. See section 3 of the ZKAP preprint (10.5281/zenodo.19698949).

Patent pending: BG/P/2026/114317, PTBG202600000316742.
"""

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Callable, List, Optional


class Status(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    CONSTRAINT_VIOLATED = "CONSTRAINT_VIOLATED"


def H(*parts: bytes) -> bytes:
    h = sha256()
    for p in parts:
        h.update(p)
    return h.digest()


@dataclass
class ChainEntry:
    """One step S_i in the per-inference hash chain.

    S_i = H( H(M) || H(C) || H(x_i) || H(y_i) || status_i || S_{i-1} )
    """
    index: int
    H_M: bytes
    H_C: bytes
    x_hash: bytes
    y_hash: bytes
    status: Status
    prev: bytes
    proof: Optional[bytes] = None
    anchor_receipt: Optional[bytes] = None

    def digest(self) -> bytes:
        return H(
            self.H_M, self.H_C, self.x_hash, self.y_hash,
            self.status.value.encode(), self.prev,
        )


@dataclass
class HashChain:
    H_M: bytes
    H_C: bytes
    entries: List[ChainEntry] = field(default_factory=list)

    @property
    def head(self) -> bytes:
        return self.entries[-1].digest() if self.entries else b"\x00" * 32

    def commit_pending(self, x_hash: bytes, y_hash: bytes) -> ChainEntry:
        entry = ChainEntry(
            index=len(self.entries),
            H_M=self.H_M,
            H_C=self.H_C,
            x_hash=x_hash,
            y_hash=y_hash,
            status=Status.PENDING,
            prev=self.head,
        )
        self.entries.append(entry)
        return entry

    def update_status(self, index: int, new_status: Status, proof: bytes) -> None:
        # In a real deployment older positions are immutable; the status
        # update is published as a follow-on attestation rather than by
        # mutating S_i. The transparency-log anchor is what makes the
        # original commitment binding.
        e = self.entries[index]
        e.status = new_status
        e.proof = proof


# Stubbed proof system. Production plugs in EZKL, Halo2, RISC Zero zkVM
# or similar and a real attestation source.
def zk_prove(satisfied: bool, public_inputs: bytes) -> bytes:
    return H(b"ZK-PROOF-STUB", b"VALID" if satisfied else b"INVALID", public_inputs)


def zk_verify(proof: bytes, public_inputs: bytes) -> bool:
    return proof == H(b"ZK-PROOF-STUB", b"VALID", public_inputs)


def anchor_to_transparency_log(entry_digest: bytes) -> bytes:
    # Production: signed-tree-head from a Sigsum log or RFC 6962 CT log.
    return H(b"SIGSUM-RECEIPT-STUB", entry_digest)


def mode_1a_inference(
    chain: HashChain,
    x: bytes,
    y: bytes,
    check_constraints: Callable[[bytes, bytes], bool],
) -> ChainEntry:
    entry = chain.commit_pending(x_hash=H(x), y_hash=H(y))
    public_inputs = entry.digest()
    proof = zk_prove(check_constraints(x, y), public_inputs)
    chain.update_status(
        entry.index,
        Status.VERIFIED if zk_verify(proof, public_inputs) else Status.CONSTRAINT_VIOLATED,
        proof,
    )
    entry.anchor_receipt = anchor_to_transparency_log(entry.digest())
    return entry


def constraints_credit_score(x: bytes, y: bytes) -> bool:
    score = int.from_bytes(y, "big") % 1000
    return 300 <= score <= 850


if __name__ == "__main__":
    chain = HashChain(
        H_M=H(b"model-credit-scorer-v3.2.1"),
        H_C=H(b"constraint-set-eu-aiact-annex-iii-2026"),
    )

    cases = [
        (b"applicant_001", (720).to_bytes(4, "big")),
        (b"applicant_002", (915).to_bytes(4, "big")),
        (b"applicant_003", (510).to_bytes(4, "big")),
    ]
    for x, y in cases:
        e = mode_1a_inference(chain, x, y, constraints_credit_score)
        print(f"S_{e.index}: {e.status.value:>21}  digest={e.digest().hex()[:16]}")
