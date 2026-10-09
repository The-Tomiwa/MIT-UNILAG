"""GPON malware framework generator.

Consumes the *results* of static/dynamic analysis (notes, strings dumps,
sandbox exports) and produces a structured response/detection framework.
It never executes or unpacks malware.
"""

from .generate import generate, correlate  # noqa: F401
