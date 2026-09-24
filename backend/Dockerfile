FROM eclipse-temurin:21-jdk-alpine

# Set Java memory constraints for Render free tier (512MB RAM total)
ENV JAVA_TOOL_OPTIONS="-Xmx350m -XX:+UseSerialGC"
ENV JADX_OPTS="-Xmx350m"

# Install system tools, Python 3, and curl
RUN apk add --no-cache python3 py3-pip py3-virtualenv bash curl wget unzip

# Install JADX CLI official release
ENV JADX_VERSION=1.5.1
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O /tmp/jadx.zip && \
    mkdir -p /opt/jadx && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    rm /tmp/jadx.zip

WORKDIR /app

# Setup Python Virtual Environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
