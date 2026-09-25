#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
# Disposable real servers and synthetic credentials only. Never uses business data.
set -euo pipefail
umask 077
task_tmp=$(mktemp -d /tmp/secretbridge-db.XXXXXXXX)
task_suffix=${task_tmp##*.}
task_pg="secretbridge-pg-$task_suffix"
task_mysql="secretbridge-mysql-$task_suffix"
task_pg_image=${SECRETBRIDGE_TEST_PG_IMAGE:-postgres:17}
task_mysql_image=${SECRETBRIDGE_TEST_MYSQL_IMAGE:-mysql:8.4}
task_db_password="Synthetic-$(openssl rand -hex 24)"
task_root_password="Synthetic-$(openssl rand -hex 24)"
printf 'POSTGRES_USER=secretbridge\nPOSTGRES_DB=secretbridge\nPOSTGRES_PASSWORD=%s\n' "$task_db_password" > "$task_tmp/postgres.env"
printf 'MYSQL_DATABASE=secretbridge\nMYSQL_USER=secretbridge\nMYSQL_PASSWORD=%s\nMYSQL_ROOT_PASSWORD=%s\n' "$task_db_password" "$task_root_password" > "$task_tmp/mysql.env"
unset task_root_password
read -r task_pg_port task_mysql_port < <(python3 - <<'PY'
import socket

sockets = []
for _ in range(2):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    sockets.append(listener)
print(*(listener.getsockname()[1] for listener in sockets))
PY
)
cleanup() {
  docker rm -f "$task_pg" "$task_mysql" >/dev/null 2>&1 || true
  case "$task_tmp" in /tmp/secretbridge-db.*) rm -rf -- "$task_tmp" ;; esac
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=SecretBridge local fixture CA' -keyout "$task_tmp/ca.key" -out "$task_tmp/ca.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=SecretBridge local fixture' -addext 'subjectAltName=IP:127.0.0.1' -keyout "$task_tmp/server.key" -out "$task_tmp/server.csr" 2>/dev/null
openssl x509 -req -in "$task_tmp/server.csr" -CA "$task_tmp/ca.pem" -CAkey "$task_tmp/ca.key" -CAcreateserial -days 2 -copy_extensions copy -out "$task_tmp/server.pem" 2>/dev/null
chmod 644 "$task_tmp/ca.pem" "$task_tmp/server.pem"
docker create --name "$task_pg" -p "127.0.0.1:$task_pg_port:5432" --env-file "$task_tmp/postgres.env" \
  "$task_pg_image" bash -c 'chown postgres:postgres /tmp/server.key; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.pem -c ssl_key_file=/tmp/server.key' >/dev/null
docker create --name "$task_mysql" -p "127.0.0.1:$task_mysql_port:3306" --env-file "$task_tmp/mysql.env" \
  "$task_mysql_image" bash -c 'chown mysql:mysql /tmp/server.key; chmod 600 /tmp/server.key; exec docker-entrypoint.sh mysqld --log-bin-trust-function-creators=ON --ssl-ca=/tmp/ca.pem --ssl-cert=/tmp/server.pem --ssl-key=/tmp/server.key' >/dev/null
for container in "$task_pg" "$task_mysql"; do
  docker cp "$task_tmp/server.key" "$container:/tmp/server.key"
  docker cp "$task_tmp/server.pem" "$container:/tmp/server.pem"
  docker cp "$task_tmp/ca.pem" "$container:/tmp/ca.pem"
  docker start "$container" >/dev/null
done
task_ready=false
for attempt in {1..60}; do
  if docker exec "$task_pg" pg_isready -U secretbridge -d secretbridge >/dev/null 2>&1 \
    && docker exec "$task_mysql" mysqladmin ping -h 127.0.0.1 --silent >/dev/null 2>&1; then
    task_ready=true
    break
  fi
  sleep 2
done
if [ "$task_ready" != true ]; then
  printf '%s\n' 'Database fixtures did not become ready.' >&2
  exit 1
fi
printf 'PostgreSQL fixture: %s\n' "$(docker exec "$task_pg" postgres --version)"
printf 'MySQL fixture: %s\n' "$(docker exec "$task_mysql" mysqld --version)"
export SECRETBRIDGE_TEST_PG_PORT
SECRETBRIDGE_TEST_PG_PORT=$task_pg_port
export SECRETBRIDGE_TEST_MYSQL_PORT
SECRETBRIDGE_TEST_MYSQL_PORT=$task_mysql_port
export SECRETBRIDGE_TEST_DB_CA="$task_tmp/ca.pem"
export SECRETBRIDGE_TEST_PG_CONTAINER="$task_pg"
export SECRETBRIDGE_TEST_MYSQL_CONTAINER="$task_mysql"
export SECRETBRIDGE_TEST_DB_PASSWORD="$task_db_password"
unset task_db_password
RUST_TEST_THREADS=1 cargo test -p secretbridge database_task::tests::real_ -- --ignored
cargo test -p secretbridge native_mcp_executes_real_databases -- --ignored
