# CyberMap AI — backend image (FastAPI)
FROM python:3.12-slim

WORKDIR /code

# psycopg2 needs libpq at runtime; build tools only for the install step.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir psycopg2-binary==2.9.10 alembic==1.14.0

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
