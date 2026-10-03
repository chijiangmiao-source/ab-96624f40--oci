FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app
COPY app ./app

USER nobody
EXPOSE 8080
CMD ["python", "-m", "app.server"]
