"""Compatibility alias: fingerprint code lives in dsoinabox.fingerprints.opengrep."""

import sys as _sys

from ..fingerprints import opengrep as _impl

_sys.modules[__name__] = _impl
