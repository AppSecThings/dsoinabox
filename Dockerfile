# syntax=docker/dockerfile:1

############################
# Stage: tools (fetch CLIs)
############################
FROM debian:bookworm-slim AS tools

# Scanner versions are pinned so two builds of the same commit produce the same
# image. Override at build time, e.g. --build-arg SYFT_VERSION=v1.52.0.
# Renovate (renovate.json) proposes bumps for these ARGs.
# renovate: datasource=github-releases depName=anchore/syft
ARG SYFT_VERSION=v1.51.1
# renovate: datasource=github-releases depName=anchore/grype
ARG GRYPE_VERSION=v0.118.0
# renovate: datasource=github-releases depName=opengrep/opengrep
ARG OPENGREP_VERSION=v1.29.0
ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl tar git bash && \
    rm -rf /var/lib/apt/lists/*

# Collect all fetched binaries here
RUN mkdir -p /out

# syft
RUN set -eux; \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /out "${SYFT_VERSION}"

# grype
RUN set -eux; \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b /out "${GRYPE_VERSION}"

# Opengrep (SAST): pinned release, arch-aware (amd64 -> x86, arm64 -> aarch64)
RUN set -eux; \
    curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh -o /tmp/opengrep-install.sh; \
    bash /tmp/opengrep-install.sh -v "${OPENGREP_VERSION}" || (echo "ERROR: opengrep installer failed with exit code $?"; exit 1); \
    if [ ! -d /root/.opengrep/cli/latest/ ]; then \
        echo "ERROR: opengrep installation directory /root/.opengrep/cli/latest/ does not exist"; \
        exit 1; \
    fi; \
    ls -la /root/.opengrep/cli/latest/; \
    if [ ! -x /root/.opengrep/cli/latest/opengrep ]; then \
        echo "ERROR: opengrep binary is not executable at /root/.opengrep/cli/latest/opengrep"; \
        echo "Directory contents:"; \
        ls -la /root/.opengrep/cli/latest/; \
        exit 1; \
    fi; \
    install -m 0755 /root/.opengrep/cli/latest/opengrep /out/opengrep

############################
# Stage: trufflehog (install script)
############################
FROM debian:bookworm-slim AS trufflehog-install

# renovate: datasource=github-releases depName=trufflesecurity/trufflehog
ARG TRUFFLEHOG_VERSION=v3.97.4
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar bash && \
    rm -rf /var/lib/apt/lists/*

# Use official installer; install into /out so we can copy to runtime
RUN set -eux; \
    mkdir -p /out; \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
      | sh -s -- -b /out "${TRUFFLEHOG_VERSION}"; \
    test -x /out/trufflehog

############################
# Stage: runtime
############################
FROM python:3.12-slim AS runtime

# renovate: datasource=pypi depName=checkov
ARG CHECKOV_VERSION=3.3.16

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

ARG APP_UID=1001
ARG APP_GID=1001

# Minimal deps for TLS trust + git
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${APP_GID}" appuser && \
    useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /usr/sbin/nologin appuser

# Bring in the tools from the "tools" stage
COPY --from=tools /out/syft /usr/local/bin/syft
COPY --from=tools /out/grype /usr/local/bin/grype
COPY --from=tools /out/opengrep /usr/local/bin/opengrep

# Bring in TruffleHog installed via script
COPY --from=trufflehog-install /out/trufflehog /usr/local/bin/trufflehog

WORKDIR /app

# Install dsoinabox from pyproject (single source of truth for dependencies)
# plus checkov, which is a Python tool.
COPY pyproject.toml LICENSE NOTICE ./
COPY dsoinabox ./dsoinabox
RUN pip install --no-cache-dir . \
    && pip install --no-cache-dir "checkov==${CHECKOV_VERSION}"

# Build-time sanity checks: every scanner and the package itself must run.
RUN trufflehog --version || (echo "trufflehog not runnable"; exit 1) \
    && checkov --version || (echo "checkov not runnable"; exit 1) \
    && syft version || (echo "syft not runnable"; exit 1) \
    && grype version || (echo "grype not runnable"; exit 1) \
    && opengrep --version || (echo "opengrep not runnable"; exit 1) \
    && python -c "import dsoinabox; print(dsoinabox.__version__)"

RUN chown -R appuser:appuser /app

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -m dsoinabox --help >/dev/null || exit 1

ENTRYPOINT ["python", "-m", "dsoinabox"]
CMD []
