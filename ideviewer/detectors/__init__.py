"""
IDE Detection modules for different platforms and IDE types.
"""

from .base import BaseDetector
from .vscode import VSCodeDetector
from .jetbrains import JetBrainsDetector
from .sublime import SublimeTextDetector
from .vim import VimDetector
from .xcode import XcodeDetector

__all__ = [
    "BaseDetector",
    "VSCodeDetector",
    "JetBrainsDetector",
    "SublimeTextDetector",
    "VimDetector",
    "XcodeDetector",
]
