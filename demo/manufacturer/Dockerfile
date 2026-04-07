FROM python:3.11-slim
WORKDIR /app

RUN pip install --no-cache-dir httpx anthropic cryptography pyjwt websockets fastapi
RUN apt-get update && apt-get install -y --no-install-recommends curl jq && rm -rf /var/lib/apt/lists/*

# Copy agent code and crypto modules
COPY agents/ ./agents/
COPY app/__init__.py ./app/__init__.py
COPY app/auth/__init__.py ./app/auth/__init__.py
COPY app/auth/message_signer.py ./app/auth/message_signer.py
COPY app/e2e_crypto.py ./app/e2e_crypto.py

COPY demo/manufacturer/entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh

CMD ["./entrypoint.sh"]
