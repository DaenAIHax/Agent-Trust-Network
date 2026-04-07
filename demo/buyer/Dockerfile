FROM python:3.11-slim
WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi uvicorn httpx anthropic cryptography pyjwt jinja2 \
    websockets python-multipart

# Copy SDK and crypto modules from main project (added at build time via docker-compose build context)
COPY agents/ ./agents/
COPY app/__init__.py ./app/__init__.py
COPY app/auth/__init__.py ./app/auth/__init__.py
COPY app/auth/message_signer.py ./app/auth/message_signer.py
COPY app/e2e_crypto.py ./app/e2e_crypto.py

# Copy standalone buyer app (AFTER app/ package to avoid overwrite)
COPY demo/buyer/app.py ./buyer_app.py
COPY demo/buyer/templates/ ./templates/

EXPOSE 3000
CMD ["uvicorn", "buyer_app:app", "--host", "0.0.0.0", "--port", "3000"]
