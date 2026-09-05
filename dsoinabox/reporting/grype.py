"""Compatibility alias: fingerprint code lives in dsoinabox.fingerprints.grype."""

import sys as _sys

from ..fingerprints import grype as _impl

_sys.modules[__name__] = _impl
