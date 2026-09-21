FROM python:3.13-slim

WORKDIR /app

# git + CA certs for the config-backup worker; the Docker CLI and Compose
# plugin so POST /stacks can run `docker compose` against the host daemon
# over the mounted socket.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && apt-get purge -y curl gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY log.py main.py connections.py sockets.py rebuild.py version.py stack_backup.py register.py deploy.py stack_deploy.py ./

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8123"]
