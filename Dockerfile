FROM python:3.12-slim

WORKDIR /app

ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y build-essential python3-dev gcc

RUN pip install --upgrade pip setuptools wheel

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY models/ models/

COPY . .

EXPOSE 5000

CMD ["python", "api/app.py"]
