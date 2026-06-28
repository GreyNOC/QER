"""GreyNOC Quantum Exposure Radar (QER).

A defensive scanner and monitor that builds a live cryptographic bill of
materials (CBOM), detects quantum-vulnerable cryptography, scores post-quantum
(PQC) migration readiness, and flags "harvest now, decrypt later" (HNDL)
exposure before attackers can exploit it.

The design principle: do not invent a new cipher. Build the thing defenders
actually lack — visibility.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
