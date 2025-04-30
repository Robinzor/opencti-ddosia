FROM python:3.11.8-slim

# Set working directory
WORKDIR /app

# Install system dependencies and update
RUN apt-get update && apt-get install -y \
    gcc \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create a non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DDOSIA_INTERVAL=300
ENV DDOSIA_UPDATE_EXISTING_DATA=true
ENV DDOSIA_CONFIDENCE_LEVEL=60
ENV DDOSIA_UPDATE_FREQUENCY=300

# Run the connector
CMD ["python", "main.py"] 