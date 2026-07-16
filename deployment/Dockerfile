# K9X Satan — Adversarial red-team harness for K9-AIF
# RHEL UBI 9 Python 3.11 container image
#
# Mirrors k9x_studio's actual pattern (see k9x-ecosystem/deployment/Dockerfile):
# k9_aif_abb comes from `pip install k9-aif` (PyPI), not a bundled/copied local
# framework checkout. Verified against PyPI k9-aif==1.8.1 (2026-07-11) — it
# already contains ShieldGovernance and everything else Satan's code path
# imports. No framework source travels in this image at all.
#
# Build (from inside satan/, after extracting the packed tarball there):
#   podman build -f deployment/Dockerfile -t k9x-satan:latest .

FROM registry.access.redhat.com/ubi9/python-311:latest

USER root

WORKDIR /app

COPY k9x_satan/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r /tmp/requirements.txt

COPY k9x_satan/ /app/k9x-ecosystem/k9x_satan/

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
