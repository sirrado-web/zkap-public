# ZKAP — Zero-Knowledge Audit Protocol

**Inventor and maintainer:** Radoslav Yordanov Radoslavov — Attorney, Legal Engineer
**Affiliation:** Advanced Consulting London
**ORCID:** [0009-0003-6868-8083](https://orcid.org/0009-0003-6868-8083)

[![Zenodo DOI](https://img.shields.io/badge/Zenodo-10.5281%2Fzenodo.19698949-blue)](https://doi.org/10.5281/zenodo.19698949)
[![License](https://img.shields.io/badge/Docs-CC--BY--4.0-green)](https://creativecommons.org/licenses/by/4.0/)
[![Status](https://img.shields.io/badge/Reference%20impl.-in%20development-orange)]()
[![Patent](https://img.shields.io/badge/Patent-BG%2FP%2F2026%2F114317%20%7C%20PTBG202600000316742-red)]()
[![Google Scholar](https://img.shields.io/badge/Google%20Scholar-Radoslavov-4285F4?logo=googlescholar&logoColor=white)](https://scholar.google.com/citations?user=S2-iyH4AAAAJ&hl=en)

---

## What is ZKAP?

**ZKAP (Zero-Knowledge Audit Protocol)** is a cryptographic enforcement protocol for verifiable regulatory compliance of machine-learning inference. It couples each ML inference with a zero-knowledge proof of constraint satisfaction — such that **the output of a non-compliant inference is physically prevented from leaving the system** rather than attested after the fact.

This is a paradigm shift from the *attestation pattern* that dominates current zero-knowledge machine-learning (ZKML) literature (e.g. RISC Zero, EZKL, zkLLM, ZKMLOps) to an *enforcement pattern* grounded in a Certified Stack construction, authority-signed polynomial constraints, and hardware- or syscall-level output gating.

## The two principal technical contributions

1. **Certified Stack with RootHash.** The ML model weights, the bit-integrity policy (integer quantisation regime), the fixed inference runtime stack, and the hardware configuration are bound together under a single cryptographic fingerprint
   ```
   RootHash(S) = H( H(M) ‖ H(BIP) ‖ H(R) ‖ H(HW) )
   ```
   which is included as a public input to every zero-knowledge proof produced by the system. Any modification to any component invalidates all subsequent proofs.

2. **Prove-before-output enforcement** in four embodiments:
   - **(A)** Hardware output gate on the physical bus.
   - **(B)** Trusted-Execution-Environment release path (Intel SGX / AMD SEV-SNP / ARM TrustZone / NVIDIA Confidential Compute).
   - **(C)** ASIC/FPGA silicon with gated output pins.
   - **(D)** Syscall-intercepting software runtime (seccomp-bpf / eBPF / kernel LSM / gVisor / nsjail).

## Three supporting mechanisms

- **Authority-signed formal constraints.** A five-type polynomial-constraint taxonomy (range, completeness, temporal, logical, counterfactual) committed as `(C, σ_C)` where `σ_C` is the signature of a Constraint Authority institutionally distinct from the Operator.
- **Per-inference hash chain with external anchoring.** An append-only chain `S_i = H(H(M) ‖ H(C) ‖ H(x_i) ‖ H(y_i) ‖ status_i ‖ S_{i−1})` periodically anchored to an external transparency log (Sigsum, Certificate Transparency, or equivalent).
- **Three-party cryptographic protocol.** Constraint Authority 𝒞 / Operator 𝒪 / Verifier 𝒱 — each role bounded by possession of a specific cryptographic capability rather than by procedural convention.

## Mode 1A — Real-time monitoring relaxation

For workloads with hard real-time constraints, ZKAP provides **Mode 1A**: output `y` is released immediately with a `PENDING` hash-chain entry; the proof is generated in parallel; on verification the chain entry is updated to `VERIFIED` or `CONSTRAINT_VIOLATED`. This relaxes strict prove-before-output to a weaker *commit-before-release* invariant.

---

## Publications

| Type | Title | DOI | Date | Access |
|---|---|---|---|---|
| **Preprint** | *ZKAP: An Enforcement Protocol for Verifiable Regulatory Compliance of ML Inference via Certified Stack Binding* | [10.5281/zenodo.19698949](https://doi.org/10.5281/zenodo.19698949) | 22 April 2026 | Metadata public; full text released after 31 March 2027 |
| **Conference paper** | *Management and Regulation of AI Models in Public Administration: Cryptographic Transparency and Digitalisation of Legal Norms* | [10.5281/zenodo.19509511](https://doi.org/10.5281/zenodo.19509511) | 11 April 2026 | Open access |
| **Conference paper v2** | *Management and Regulation of AI Models in Public Administration* (extended) | [10.5281/zenodo.19638683](https://doi.org/10.5281/zenodo.19638683) | 18 April 2026 | Open access |
| **Concept paper** | *Management and Regulation of Artificial Intelligence Models: Concept for Transparency and Accountability in Administrative Activities* | [10.5281/zenodo.19614243](https://doi.org/10.5281/zenodo.19614243) | 2025 | Open access (Industry 4.0) |

## Patent applications

| Number | Title (working) | Filing | Status |
|---|---|---|---|
| **BG/P/2026/114317** | Hardware ZKAP — Certified Stack with RootHash, prove-before-output in hardware embodiments | 30 March 2026 | Filed at BPO (amended 11 April 2026, EFBG202600000316739) |
| **PTBG202600000316742** | Software ZKAP — syscall-intercepting runtime with Certified Stack binding | 12 April 2026 | Filed at BPO |
| **UK/EPO/PCT V6.0 PRECISE** | International application: three-independent-claim structure (Certified Stack, Pre-commitment Mode 1A, Transparency-Log Anchoring) | in preparation | Paris Convention window: 30 March 2027 (BG1) / 12 April 2027 (BG2) |

## Related work and positioning

ZKAP is positioned against, and complementary to, the **ZKMLOps framework** (Scaramuzza, Cordeiro Ferreira, Maia Suller, Quattrocchi, Tamburri, van den Heuvel — Tilburg University, Eindhoven University of Technology, Politecnico di Milano, University of Sannio, arXiv:2505.20136 and arXiv:2510.26576). ZKMLOps operates at the software-engineering / MLOps-lifecycle-integration layer; ZKAP operates at the cryptographic-enforcement-architecture layer. The two works address different aspects of the same broader problem and are positioned as **complementary** rather than competing contributions. For detailed prior-art relationship, see Section 2 and Appendix A of the Zenodo preprint.

## Reference implementation

A working implementation is currently in development. An initial minimal proof-of-concept covering Embodiment D (syscall interception on Linux), authority signing of a small constraint set, RootHash computation over a toy Certified Stack, and Sigsum-anchored chain is planned for a later release. The current Zenodo preprint specifies the protocol at a level sufficient for independent reimplementation.

## Licence

- **Documentation and text content:** Creative Commons Attribution 4.0 International (CC-BY-4.0). See [LICENSE-DOCS](./LICENSE-DOCS.md).
- **Patent claims:** subject to pending patent applications BG/P/2026/114317, PTBG202600000316742, and the forthcoming UK/EPO/PCT V6.0 PRECISE international application. Academic research and educational use of the described constructions is expressly permitted; commercial use within a ZKAP-architecture deployment is subject to the patent licence terms to be published.

## Contact

- **Author:** Radoslav Y. Radoslavov
- **Practice:** Advanced Consulting London
- **Address:** 4 Atkinson Road, Royal Docks, London, E16 3LR, United Kingdom
- **Email:** [zkap@advanced-consulting.london](mailto:zkap@advanced-consulting.london)
- **Websites:** [advanced-consulting.london](https://advanced-consulting.london) | [radoslavov.bg](https://www.radoslavov.bg/)

For licensing enquiries, institutional pilot-project proposals, or academic collaboration, please use the email above with subject line `[ZKAP]`.

## Citing this work

If you reference ZKAP in a publication, please cite the Zenodo preprint:

```bibtex
@misc{radoslavov2026zkap,
  author       = {Radoslavov, Radoslav Yordanov},
  title        = {ZKAP: An Enforcement Protocol for Verifiable Regulatory Compliance of Machine-Learning Inference via Certified Stack Binding},
  year         = {2026},
  month        = apr,
  publisher    = {Zenodo},
  version      = {1.0},
  doi          = {10.5281/zenodo.19698949},
  url          = {https://doi.org/10.5281/zenodo.19698949},
  note         = {Preprint, embargoed until 31 March 2027}
}
```

## Acknowledgements

This work builds upon the cumulative contributions of the zero-knowledge proof community, including the foundational work of Goldwasser, Micali and Rackoff (1985) on interactive proof systems, Groth (2016) on succinct arguments, the Halo2 and Nova proof-system families, the EZKL and RISC Zero engineering efforts, Kusner et al. (2017) on counterfactual fairness, and the Sigsum and Certificate Transparency transparency-log infrastructures. Specific references appear in the Zenodo preprint.

---

*This repository is a public information hub for ZKAP. No implementation code is currently published; see the "Reference implementation" section above.*
