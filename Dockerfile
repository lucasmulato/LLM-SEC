FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HOME=/tmp

WORKDIR /app

COPY pyproject.toml README.md ./
COPY llmsec/ ./llmsec/
COPY core/ ./core/
COPY mcp_server/ ./mcp_server/

RUN pip install --no-cache-dir '.[mcp]'

USER 10001:10001

CMD ["llmsec-mcp"]
