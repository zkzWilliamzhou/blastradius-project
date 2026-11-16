"""blastradius —— know the blast radius before you press enter.

Pure stdlib. No execution, ever: commands are parsed and scored as text.
"""

from .score import assess, score_findings, worst_severity  # noqa: F401
from .rules import analyze, Finding  # noqa: F401
from .policy import Policy, evaluate, PRESETS  # noqa: F401

__version__ = "1.0.0"
