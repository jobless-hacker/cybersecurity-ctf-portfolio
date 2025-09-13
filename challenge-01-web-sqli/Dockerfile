FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY source-code/ ./source-code/
RUN mkdir -p database

EXPOSE 5000

CMD ["python", "source-code/vulnerable_app.py"]
