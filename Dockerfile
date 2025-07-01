# chayabusaw/Dockerfile

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    HAYABUSA_VERSION=3.3.0

# Install system deps for building hayabusa
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      wget unzip git build-essential curl ca-certificates libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Bring in rustup and set up a current Rust toolchain
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path \
 && rustup toolchain install stable \
 && rustup default stable

# Clone & build hayabusa from source
ARG HAYABUSA_VERSION=3.3.0
RUN git clone --depth 1 --branch v${HAYABUSA_VERSION} \
      https://github.com/Yamato-Security/hayabusa.git /build/hayabusa \
 && cd /build/hayabusa \
 && cargo build --release \
 && mv target/release/hayabusa /usr/local/bin/ \
 && chmod +x /usr/local/bin/hayabusa \
 && rm -rf /build/hayabusa

# Install Chainsaw (as before)
COPY ./chainsaw /chainsaw
RUN mv /chainsaw/chainsaw /usr/local/bin/chainsaw \
 && chmod +x /usr/local/bin/chainsaw

# Verify both tools
RUN hayabusa help && chainsaw --version

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY ./app /app
EXPOSE 8000
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000"]
