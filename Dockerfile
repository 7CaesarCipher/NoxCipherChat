FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY relay_server.py .
EXPOSE 8765
CMD ["uvicorn", "relay_server:app", "--host", "0.0.0.0", "--port", "8765", "--no-access-log"]
