# K9X Satan — Adversarial red-team harness for K9-AIF
# RHEL UBI 9 Python 3.11 container image
#
# k9_aif_abb comes from `pip install k9-aif` (PyPI), pulled in transitively
# by installing this package itself — pyproject.toml declares
# `k9-aif>=1.9.0` as a dependency, and `pip install .` resolves it from
# PyPI along with every other dependency. No framework source travels in
# this image, and no separate git-clone step is needed.
#
# Requires k9-aif>=1.9.0 to be published on PyPI (added ToolAuthorizationCheck,
# MemoryPoisoningCheck, SystemPromptLeakageCheck, OutputSanitizationCheck,
# RequestFrequencyCheck, RoleBasedAuthorizationGuard — all imported by
# target/router.py and target/orchestrator.py). An older k9-aif on PyPI
# will fail at import time with a clear ModuleNotFoundError, not a silent
# stub — if this build fails on import, check `pip index versions k9-aif`
# against the version pinned here before assuming anything else is wrong.
#
# Build (from inside satan/, after extracting the packed tarball there):
#   podman build -f deployment/Dockerfile -t k9x-satan:latest .

FROM registry.access.redhat.com/ubi9/python-311:latest

USER root

WORKDIR /app/k9x-ecosystem/k9x_satan

# Copy the full package (pyproject.toml + source + package-data) and
# install it — this is what resolves k9-aif from PyPI, not a separate step.
# pip installs k9x_satan properly into site-packages, so no PYTHONPATH
# trick is needed for `uvicorn k9x_satan.app:app` to find it.
COPY k9x_satan/ /app/k9x-ecosystem/k9x_satan/

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir .

# K9_ENV must stay "development" — Satan is a test harness, not a production
# business app. k9_aif_abb's governance rule makes enforce_governance() RAISE
# in production/staging when NoopGovernance is active, and every agent in
# target/agents.py calls enforce_governance(). Setting this to "production"
# would make every attack show a generic squad_error instead of a real
# BLOCKED/COMPLETED verdict — see config/config.yaml's own comment.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    K9_ENV=development

EXPOSE 6660

HEALTHCHECK --interval=30s --timeout=8s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:6660/api/health')" \
      || exit 1

USER 1001

CMD ["uvicorn", "k9x_satan.app:app", "--host", "0.0.0.0", "--port", "6660", "--log-level", "info"]
