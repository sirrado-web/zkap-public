"""
Software output gate for Embodiment D of ZKAP. The gate intercepts
output system calls of the operator process and releases each chunk
only after a zero-knowledge proof bound to the same RootHash has been
verified. Production deployments use seccomp-bpf with a userspace
supervisor, eBPF LSM hooks, a kernel LSM module, or runtimes such as
gVisor or nsjail; here the intercept is simulated in pure Python so
the control flow can be inspected without specialised hardware. See
the preprint at 10.5281/zenodo.19698949 for the full architecture.

Patent pending: BG/P/2026/114317, PTBG202600000316742.
"""

import logging
from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Optional


log = logging.getLogger("zkap.embodiment_d")


def H(*parts: bytes) -> bytes:
    h = sha256()
    for p in parts:
        h.update(p)
    return h.digest()


@dataclass(frozen=True)
class ProofVerifier:
    name: str
    verify: Callable[[bytes, bytes], bool]


def stub_verifier() -> ProofVerifier:
    """Stub that accepts proof iff it equals H('VALID-PROOF', public_inputs)."""
    return ProofVerifier(
        name="stub-sha256-verifier",
        verify=lambda proof, pub: proof == H(b"VALID-PROOF", pub),
    )


class OutputGateBlocked(Exception):
    pass


@dataclass
class GateConfig:
    root_hash: bytes
    constraint_set_hash: bytes
    proof_max_age_seconds: int = 60


@dataclass
class GuardedOutput:
    inference_id: bytes
    payload: bytes
    proof: bytes
    public_inputs: bytes
    timestamp: int


@dataclass
class TransparencyLogEntry:
    inference_id: bytes
    payload_hash: bytes
    decision: str
    public_inputs: bytes


class SyscallOutputGate:
    """Releases a payload only when the proof is valid and bound to the
    pinned Certified Stack and constraint set."""

    def __init__(self, cfg: GateConfig, verifier: ProofVerifier):
        self.cfg = cfg
        self.verifier = verifier
        self._log: list[TransparencyLogEntry] = []

    def write(self, request: GuardedOutput) -> bytes:
        self._reject_if_root_hash_drift(request.public_inputs)
        self._reject_if_proof_invalid(request)
        self._log_release(request)
        return request.payload

    @property
    def transparency_log(self):
        return iter(self._log)

    def _reject_if_root_hash_drift(self, public_inputs: bytes) -> None:
        if self.cfg.root_hash.hex().encode() not in public_inputs:
            raise OutputGateBlocked("RootHash drift in public inputs.")
        if self.cfg.constraint_set_hash.hex().encode() not in public_inputs:
            raise OutputGateBlocked("Constraint-set hash drift in public inputs.")

    def _reject_if_proof_invalid(self, request: GuardedOutput) -> None:
        if not self.verifier.verify(request.proof, request.public_inputs):
            self._log.append(TransparencyLogEntry(
                inference_id=request.inference_id,
                payload_hash=H(request.payload),
                decision="BLOCKED",
                public_inputs=request.public_inputs,
            ))
            raise OutputGateBlocked("Proof verification failed.")

    def _log_release(self, request: GuardedOutput) -> None:
        self._log.append(TransparencyLogEntry(
            inference_id=request.inference_id,
            payload_hash=H(request.payload),
            decision="RELEASED",
            public_inputs=request.public_inputs,
        ))


class GuardedInferenceOperator:
    """Routes every output through the gate. Application code never
    holds a reference to the gate's internal state."""

    def __init__(self, gate: SyscallOutputGate):
        self._gate = gate

    def emit(self, inference_id: bytes, payload: bytes, proof: bytes,
             public_inputs: bytes, timestamp: int) -> Optional[bytes]:
        try:
            return self._gate.write(GuardedOutput(
                inference_id=inference_id,
                payload=payload,
                proof=proof,
                public_inputs=public_inputs,
                timestamp=timestamp,
            ))
        except OutputGateBlocked as exc:
            log.warning("output blocked: %s", exc)
            return None


def make_public_inputs(root_hash: bytes, c_hash: bytes,
                       x_hash: bytes, y_hash: bytes) -> bytes:
    return (
        b"root=" + root_hash.hex().encode() + b"|"
        b"C=" + c_hash.hex().encode() + b"|"
        b"x=" + x_hash.hex().encode() + b"|"
        b"y=" + y_hash.hex().encode()
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    pinned_root = H(b"certified-stack-credit-scorer-v3")
    pinned_c = H(b"aiact-annex-iii-constraints")

    gate = SyscallOutputGate(
        cfg=GateConfig(root_hash=pinned_root, constraint_set_hash=pinned_c),
        verifier=stub_verifier(),
    )
    operator = GuardedInferenceOperator(gate)

    pi = make_public_inputs(pinned_root, pinned_c, H(b"x1"), H(b"y1"))
    proof_ok = H(b"VALID-PROOF", pi)
    print("case 1 valid -> released:",
          operator.emit(b"inf-001", b"score=720", proof_ok, pi, 1_730_000_000))

    pi2 = make_public_inputs(pinned_root, pinned_c, H(b"x2"), H(b"y2"))
    bad_proof = H(b"FORGED", pi2)
    print("case 2 forged -> released:",
          operator.emit(b"inf-002", b"score=915", bad_proof, pi2, 1_730_000_001))

    rogue_root = H(b"rogue-stack")
    pi3 = make_public_inputs(rogue_root, pinned_c, H(b"x3"), H(b"y3"))
    proof3 = H(b"VALID-PROOF", pi3)
    print("case 3 drift -> released:",
          operator.emit(b"inf-003", b"score=600", proof3, pi3, 1_730_000_002))

    print()
    for e in gate.transparency_log:
        print(f"  {e.decision:>9}  inf={e.inference_id.decode():<10} "
              f"payload={e.payload_hash.hex()[:16]}")
