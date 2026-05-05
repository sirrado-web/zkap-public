"""
Computes the RootHash that binds the four components of a Certified
Stack into a single fingerprint, as defined in the ZKAP preprint
(10.5281/zenodo.19698949):

    RootHash(S) = H( H(M) || H(BIP) || H(R) || H(HW) )

where M is the model weights, BIP is the bit-integrity policy, R is
the runtime stack, HW is the hardware configuration. Any modification
to any component yields a different RootHash and invalidates all
proofs produced under the previous one. Production deployments use
SHA3-256 or BLAKE3; SHA-256 is used here for portability with common
zk-SNARK gadgets.

Patent pending: BG/P/2026/114317, PTBG202600000316742.
"""

import hashlib
import json
from dataclasses import asdict, dataclass


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@dataclass(frozen=True)
class ModelComponent:
    architecture: str
    parameter_count: int
    weights_digest: str
    framework: str


@dataclass(frozen=True)
class BitIntegrityPolicy:
    integer_bits: int
    rounding_mode: str
    overflow_behaviour: str
    dtype: str


@dataclass(frozen=True)
class RuntimeStack:
    os_kernel: str
    inference_lib: str
    crypto_lib: str
    seccomp_profile_digest: str


@dataclass(frozen=True)
class HardwareConfig:
    cpu_model: str
    cpu_microcode: str
    tee_type: str
    tee_attestation_pubkey: str
    pci_topology_hash: str


def _canon(obj) -> bytes:
    """Deterministic JSON encoding so two parties get the same digest."""
    return json.dumps(
        asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def H_M(model: ModelComponent) -> bytes:
    return H(_canon(model))


def H_BIP(policy: BitIntegrityPolicy) -> bytes:
    return H(_canon(policy))


def H_R(runtime: RuntimeStack) -> bytes:
    return H(_canon(runtime))


def H_HW(hw: HardwareConfig) -> bytes:
    return H(_canon(hw))


def root_hash(model, policy, runtime, hw) -> bytes:
    return H(H_M(model) + H_BIP(policy) + H_R(runtime) + H_HW(hw))


if __name__ == "__main__":
    model = ModelComponent(
        architecture="transformer-decoder",
        parameter_count=7_000_000_000,
        weights_digest="9c3a" + "0" * 60,
        framework="torch-2.4",
    )
    policy = BitIntegrityPolicy(
        integer_bits=8,
        rounding_mode="banker",
        overflow_behaviour="saturate",
        dtype="int8",
    )
    runtime = RuntimeStack(
        os_kernel="linux-6.6.42",
        inference_lib="onnxruntime-1.17.0",
        crypto_lib="libsodium-1.0.20",
        seccomp_profile_digest="b2f1" + "0" * 60,
    )
    hw = HardwareConfig(
        cpu_model="Intel Xeon 8480+",
        cpu_microcode="0x2b000620",
        tee_type="TDX",
        tee_attestation_pubkey="ed25519:abcdef" + "0" * 54,
        pci_topology_hash="ccaa" + "0" * 60,
    )

    print(f"H(M)   = {H_M(model).hex()}")
    print(f"H(BIP) = {H_BIP(policy).hex()}")
    print(f"H(R)   = {H_R(runtime).hex()}")
    print(f"H(HW)  = {H_HW(hw).hex()}")
    print(f"Root   = {root_hash(model, policy, runtime, hw).hex()}")

    tampered = RuntimeStack(
        os_kernel="linux-6.6.43",
        inference_lib=runtime.inference_lib,
        crypto_lib=runtime.crypto_lib,
        seccomp_profile_digest=runtime.seccomp_profile_digest,
    )
    print()
    print("After kernel patch 6.6.42 -> 6.6.43:")
    print(f"  new Root = {root_hash(model, policy, tampered, hw).hex()}")
