# Base image policy: openSUSE / SUSE BCI only.
#
# SUSE BCI Python (SLE-based, SUSE-supported lifecycle) is the build and runtime
# base. The openSUSE equivalent, registry.opensuse.org/opensuse/bci/python, is
# the only other permitted base -- but as of 2026-07 its :3.13 manifest list
# publishes no linux/amd64 image (arm, arm64, ppc64le, riscv64 and s390x only),
# so swapping to it breaks the build on x86_64. Its :3.12 tag does carry amd64.
# No base outside those two is permitted here.
#
#   builder : creates a self-contained venv with pinned wheels
#   runtime  : copies the venv, drops privileges, no compilers on the final image

FROM registry.suse.com/bci/python:3.13 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /build
RUN python3 -m venv "$VIRTUAL_ENV"

# Dependency layer first so source edits do not invalidate the wheel cache.
COPY pyproject.toml README.md ./
COPY src ./src
RUN python3 -m pip install --upgrade pip setuptools wheel \
 && python3 -m pip install .

# ------------------------------------------------------------------------------
FROM registry.suse.com/bci/python:3.13 AS runtime

LABEL org.opencontainers.image.title="neuvector-mcp" \
      org.opencontainers.image.description="MCP server for SUSE NeuVector" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="registry.suse.com/bci/python:3.13"

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NV_TRANSPORT=http \
    NV_HTTP_HOST=0.0.0.0 \
    NV_HTTP_PORT=8080 \
    NV_READ_ONLY=true \
    NV_LOG_FORMAT=json

COPY --from=builder /opt/venv /opt/venv

# Fixed uid/gid so a PodSecurity "restricted" namespace can pin runAsUser.
RUN groupadd --gid 10001 nvmcp \
 && useradd  --uid 10001 --gid 10001 --home-dir /home/nvmcp --create-home --shell /sbin/nologin nvmcp \
 && chown -R 10001:10001 /opt/venv

USER 10001:10001
WORKDIR /home/nvmcp
EXPOSE 8080

# The server exposes no HTTP health path of its own; a TCP probe on the MCP port
# is the correct liveness signal. See deploy/deployment.yaml.
ENTRYPOINT ["neuvector-mcp"]
