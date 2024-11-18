FROM python:3.12-slim

# Set environment variables to prevent pyc files and enable virtual environments
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    python3-dev \
    libpcap-dev \
    tcpdump \
    libffi-dev \
    && apt-get clean autoclean \
    ** apt-get autoremove --yes \
    && rm -rf /var/lib/apt/lists/*

# Install pipenv
RUN pip install --upgrade pip && \
    pip install pipenv

# Set the working directory in the container
WORKDIR /app

# Copy the current directory into the container
COPY server/*.py .
COPY Pipfile .

# Install dependencies using pipenv
RUN pipenv install

# Define the entry point to allow running your Python script
ENTRYPOINT ["pipenv", "run", "python", "fultonserver.py"]