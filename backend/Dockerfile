FROM python:3.11-slim

# Install dependencies
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose port and run application
EXPOSE 5000
CMD ["python", "app.py"]

