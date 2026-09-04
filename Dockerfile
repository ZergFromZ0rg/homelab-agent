FROM python:3.13-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py stack_backup.py register.py ./

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8123"]
