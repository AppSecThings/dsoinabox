from pathlib import Path

try:
    from importlib.metadata import PackageNotFoundError, version
except ImportError:  # pragma: no cover
    from importlib_metadata import PackageNotFoundError, version


def _read_local_version() -> str:
    import tomllib

    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject_path.open("rb") as pyproject_file:
        project = tomllib.load(pyproject_file)["project"]
    return project["version"]


try:
    __version__ = _read_local_version()
except Exception:
    try:
        __version__ = version("dsoinabox")
    except PackageNotFoundError:
        __version__ = "0.0.0"
