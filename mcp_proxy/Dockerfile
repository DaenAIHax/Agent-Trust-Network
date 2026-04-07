FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY mcp_proxy/requirements-proxy.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy proxy code + SDK
COPY mcp_proxy/ ./mcp_proxy/
COPY cullis_sdk/ ./cullis_sdk/

# Data directory for SQLite
RUN mkdir -p /data && \
    useradd --no-create-home --system proxyuser && \
    chown proxyuser:proxyuser /data

ENV PYTHONPATH=/app
ENV MCP_PROXY_DATABASE_URL=sqlite+aiosqlite:////data/mcp_proxy.db

EXPOSE 9100

USER proxyuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9100/health')" || exit 1

CMD ["uvicorn", "mcp_proxy.main:app", "--host", "0.0.0.0", "--port", "9100"]
