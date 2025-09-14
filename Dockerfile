FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential python3-dev gcc

RUN pip install --upgrade pip setuptools wheel

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN ls -l /app/models && ls -l /app/api


COPY . .

EXPOSE 5000

CMD ["python", "api/app.py"]
