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
      https://github.com/Yamato-Security/hayabusa.git /opt/hayabusa \
 && cd /opt/hayabusa \
 && cargo build --release \
 && mv target/release/hayabusa /opt/hayabusa/ \
 && chmod +x /opt/hayabusa/hayabusa \
 && ln -s /opt/hayabusa/hayabusa /usr/local/bin/hayabusa \
 && rm -rf /opt/hayabusa/target /opt/hayabusa/.git

# Install Chainsaw (as before)
COPY ./chainsaw /chainsaw
RUN mv /chainsaw/chainsaw /usr/local/bin/chainsaw \
 && chmod +x /usr/local/bin/chainsaw

# Verify both tools
RUN hayabusa help && chainsaw --version

# Clone upstream Sigma rules into /opt/sigma/default
RUN git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/sigma/default

# Clone chainsaw repo for default rules
RUN git clone --depth 1 https://github.com/WithSecureLabs/chainsaw.git /opt/chainsaw

# Create a mount‐point for custom rules
RUN mkdir -p /opt/sigma/custom \
 && mkdir -p /chainsaw-rules

# Copy entrypoint script in
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Install our app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY ./app /app
ENTRYPOINT ["entrypoint.sh"]
EXPOSE 8000
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000"]
