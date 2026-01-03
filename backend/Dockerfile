FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY scanner/ ./scanner/

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
