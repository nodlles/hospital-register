FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    HOSPITAL_CONFIG=/app/.hospital-register/config.local.json

WORKDIR /app

COPY hospital_watch.py app_server.py config.example.json README.md ./
COPY web ./web

EXPOSE 8000

CMD ["python", "app_server.py"]
