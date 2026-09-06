"""Compatibility alias: fingerprint code lives in dsoinabox.fingerprints.checkov."""

import sys as _sys

from ..fingerprints import checkov as _impl

_sys.modules[__name__] = _impl
