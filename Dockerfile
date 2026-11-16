FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md PROJECT_DESCRIPTION.md PROJECT_TASKS.md ./
COPY target_app ./target_app
COPY firewall ./firewall
COPY fuzzer ./fuzzer
COPY evaluation ./evaluation
RUN pip install --no-cache-dir ".[storage]" \
    && useradd --system --uid 10001 --create-home appuser \
    && chown -R appuser:appuser /app

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["uvicorn", "firewall.gateway.app:app", "--host", "0.0.0.0", "--port", "8000"]
