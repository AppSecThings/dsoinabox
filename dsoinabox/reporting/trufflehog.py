"""Compatibility alias: fingerprint code lives in dsoinabox.fingerprints.trufflehog."""

import sys as _sys

from ..fingerprints import trufflehog as _impl

_sys.modules[__name__] = _impl
