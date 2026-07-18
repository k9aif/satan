# K9X Satan — Adversarial red-team harness for K9-AIF
# RHEL UBI 9 Python 3.11 container image
#
# k9_aif_abb comes from a git clone of the framework repo, NOT `pip install
# k9-aif` — PyPI's published k9-aif is currently behind the framework's
# GitHub main branch (still 1.8.2; this build needs the checks/guards added
# after that release: ToolAuthorizationCheck, MemoryPoisoningCheck,
# SystemPromptLeakageCheck, OutputSanitizationCheck, RequestFrequencyCheck,
# RoleBasedAuthorizationGuard). Once k9-aif>=1.9.0 is actually published on
# PyPI, this can switch back to a plain `pip install k9-aif>=1.9.0` step —
# until then, git clone is the only way to get code that's on GitHub but
# not yet released.
#
# Build (from inside satan/, after extracting the packed tarball there):
#   podman build -f deployment/Dockerfile -t k9x-satan:latest .

FROM registry.access.redhat.com/ubi9/python-311:latest

USER root

# Install Git for retrieving the K9-AIF framework.
RUN dnf install -y git \
    && dnf clean all \
    && rm -rf /var/cache/dnf

WORKDIR /app/k9x-ecosystem

# Copy dependency file first so this layer remains cached unless
# requirements.txt changes.
COPY k9x_satan/requirements.txt /tmp/requirements.txt

# Install SATAN dependencies.
# The grep provides protection in case k9-aif is accidentally
# left in requirements.txt — the framework comes from git clone below,
# not PyPI, while PyPI is behind GitHub main.
RUN grep -viE '^[[:space:]]*k9-aif([<>=!~].*)?[[:space:]]*$' \
        /tmp/requirements.txt > /tmp/requirements-filtered.txt \
    && python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
        -r /tmp/requirements-filtered.txt

# This value controls only the K9-AIF framework cache layer.
#
# Leave it unchanged for quick cached builds.
# Increment it only when new framework code must be pulled:
#   --build-arg K9AIF_CACHE_VERSION=2
ARG K9AIF_CACHE_VERSION=1

RUN echo "K9-AIF cache version: ${K9AIF_CACHE_VERSION}" \
    && git clone --depth 1 \
        https://github.com/k9aif/k9-aif-framework.git \
        /tmp/k9-aif-framework \
    && python -m pip install --no-cache-dir /tmp/k9-aif-framework \
    && rm -rf /tmp/k9-aif-framework

# Copy SATAN after installing dependencies.
# Changes to SATAN source will not invalidate the dependency layers above.
COPY k9x_satan /app/k9x-ecosystem/k9x_satan

WORKDIR /app/k9x-ecosystem/k9x_satan

# K9_ENV must stay "development" — Satan is a test harness, not a production
# business app. k9_aif_abb's governance rule makes enforce_governance() RAISE
# in production/staging when NoopGovernance is active, and every agent in
# target/agents.py calls enforce_governance(). Setting this to "production"
# would make every attack show a generic squad_error instead of a real
# BLOCKED/COMPLETED verdict — see config/config.yaml's own comment.
ENV PYTHONPATH=/app/k9x-ecosystem \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    K9_ENV=development

EXPOSE 6660

HEALTHCHECK --interval=30s --timeout=8s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:6660/api/health')" \
      || exit 1

USER 1001

CMD ["uvicorn", "k9x_satan.app:app", "--host", "0.0.0.0", "--port", "6660", "--log-level", "info"]
