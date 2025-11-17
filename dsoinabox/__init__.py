try:
    from importlib.metadata import version
    __version__ = version("dsoinabox")
except ImportError:
    # python < 3.8
    try:
        from importlib_metadata import version
        __version__ = version("dsoinabox")
    except ImportError:
        # fallback to setuptools_scm for dev (when not installed)
        try:
            from setuptools_scm import get_version
            __version__ = get_version(root='..', relative_to=__file__)
        except (ImportError, LookupError):
            __version__ = "0.0.0"
except Exception:
    # fallback to setuptools_scm for dev (when not installed)
    try:
        from setuptools_scm import get_version
        __version__ = get_version(root='..', relative_to=__file__)
    except (ImportError, LookupError):
        __version__ = "0.0.0"
