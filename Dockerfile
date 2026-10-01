FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl dnsutils ffuf git nmap whatweb \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 vapt \
    && useradd --uid 10001 --gid 10001 --create-home vapt

WORKDIR /opt/matt-vapt-kit
COPY pyproject.toml README.md ./
COPY vaptkit ./vaptkit
RUN pip install --no-cache-dir .

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["vapt"]
CMD ["--help"]
