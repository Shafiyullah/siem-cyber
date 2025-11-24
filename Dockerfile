# In Dockerfile

# --- Stage 1: Builder ---
# We use a full Python image to install packages
FROM python:3.14 as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install
COPY requirements.txt .
# Update requirements.txt to REMOVE transformers, sentence-transformers, torch
# And ADD vaderSentiment, aiofiles
RUN pip install --no-cache-dir -r requirements.txt


# --- Stage 2: Final Runtime ---
# We use a slim image for the final, lightweight container
FROM python:3.14-slim

# Create non-root user
RUN useradd -m siemuser
USER siemuser
WORKDIR /app

# Copy the virtual environment from the builder stage
COPY --chown=siemuser:siemuser --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=siemuser:siemuser . .

# Set environment
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 8000

# Run the API server.
# This CMD runs main.py, which in turn runs uvicorn
CMD ["python", "main.py"]