FROM python:3.12-slim

LABEL maintainer="Strikerr Security Architecture Team <security@strikerr.id>"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    django>=5.1,<6.0 \
    psycopg[binary]>=3.2 \
    celery[redis,rabbitmq]>=5.4.0 \
    redis>=5.0.0 \
    curl_cffi>=0.7.2 \
    httpx>=0.27.0 \
    dnspython>=2.6.1 \
    pyahocorasick>=2.1.0 \
    beautifulsoup4>=4.12.0 \
    lxml>=5.3.0 \
    tldextract>=5.1.2 \
    cryptography>=43.0.0 \
    minio>=7.2.7 \
    pydantic>=2.8.0 \
    reportlab>=4.2.0

COPY ./strikerr /app/strikerr
COPY ./manage.py /app/manage.py

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
