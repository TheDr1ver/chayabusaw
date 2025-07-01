# evtx-analyzer/Dockerfile

# Use a slim Python base image
FROM python:3.12-slim

# Set environment variables for non-interactive installs
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies: wget for downloading and unzip for extracting archives
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip && \
    rm -rf /var/lib/apt/lists/*

# --- Install Hayabusa ---
# Find the latest release URL from GitHub API
# Using a fixed version for reproducibility. Update the version as needed.
ARG HAYABUSA_VERSION=2.12.0
ARG HAYABUSA_URL=https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-v${HAYABUSA_VERSION}-linux.zip
RUN wget -q ${HAYABUSA_URL} -O hayabusa.zip && \
    unzip hayabusa.zip && \
    # The binary is inside a directory, find it and move it to the PATH
    mv hayabusa-v*/hayabusa /usr/local/bin/hayabusa && \
    chmod +x /usr/local/bin/hayabusa && \
    rm -rf hayabusa.zip hayabusa-v*

# --- Install Chainsaw ---
# Using a fixed version for reproducibility. Update the version as needed.
ARG CHAINSAW_VERSION=2.12.2
ARG CHAINSAW_URL=https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_x86_64-unknown-linux-gnu.tar.gz
RUN wget -q ${CHAINSAW_URL} -O chainsaw.tar.gz && \
    tar -xzf chainsaw.tar.gz && \
    mv chainsaw /usr/local/bin/chainsaw && \
    chmod +x /usr/local/bin/chainsaw && \
    rm -rf chainsaw.tar.gz

# Verify installations
RUN chainsaw --version && hayabusa --version

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy the application code into the container
COPY ./app /app

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application using uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]