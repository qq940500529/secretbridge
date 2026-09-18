#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
# Disposable real servers and synthetic credentials only. Never uses business data.
set -euo pipefail
task_tmp=$(mktemp -d /tmp/secretbridge-db.XXXXXXXX)
task_suffix=${task_tmp##*.}
task_pg="secretbridge-pg-$task_suffix"
task_mysql="secretbridge-mysql-$task_suffix"
cleanup() {
  docker rm -f "$task_pg" "$task_mysql" >/dev/null 2>&1 || true
  case "$task_tmp" in /tmp/secretbridge-db.*) rm -rf -- "$task_tmp" ;; esac
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=SecretBridge local fixture CA' -keyout "$task_tmp/ca.key" -out "$task_tmp/ca.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=SecretBridge local fixture' -addext 'subjectAltName=IP:127.0.0.1' -keyout "$task_tmp/server.key" -out "$task_tmp/server.csr" 2>/dev/null
openssl x509 -req -in "$task_tmp/server.csr" -CA "$task_tmp/ca.pem" -CAkey "$task_tmp/ca.key" -CAcreateserial -days 2 -copy_extensions copy -out "$task_tmp/server.pem" 2>/dev/null
docker create --name "$task_pg" -p 127.0.0.1::5432 \
  -e POSTGRES_USER=secretbridge -e POSTGRES_DB=secretbridge -e POSTGRES_PASSWORD=Synthetic_db_password_30 \
  postgres:17 bash -c 'chown postgres:postgres /tmp/server.key; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.pem -c ssl_key_file=/tmp/server.key' >/dev/null
docker create --name "$task_mysql" -p 127.0.0.1::3306 \
  -e MYSQL_DATABASE=secretbridge -e MYSQL_USER=secretbridge -e MYSQL_PASSWORD=Synthetic_db_password_30 -e MYSQL_ROOT_PASSWORD=Synthetic_root_fixture_30 \
  mysql:8.4 bash -c 'chown mysql:mysql /tmp/server.key; chmod 600 /tmp/server.key; exec docker-entrypoint.sh mysqld --log-bin-trust-function-creators=ON --ssl-ca=/tmp/ca.pem --ssl-cert=/tmp/server.pem --ssl-key=/tmp/server.key' >/dev/null
for container in "$task_pg" "$task_mysql"; do
  docker cp "$task_tmp/server.key" "$container:/tmp/server.key"
  docker cp "$task_tmp/server.pem" "$container:/tmp/server.pem"
  docker cp "$task_tmp/ca.pem" "$container:/tmp/ca.pem"
  docker start "$container" >/dev/null
done
task_ready=false
for attempt in {1..60}; do
  if docker exec "$task_pg" pg_isready -U secretbridge -d secretbridge >/dev/null 2>&1 \
    && docker exec -e MYSQL_PWD=Synthetic_db_password_30 "$task_mysql" mysql -h 127.0.0.1 -u secretbridge secretbridge -e 'SELECT 1' >/dev/null 2>&1; then
    task_ready=true
    break
  fi
  sleep 2
done
if [ "$task_ready" != true ]; then
  printf '%s\n' 'Database fixtures did not become ready.' >&2
  exit 1
fi
export SECRETBRIDGE_TEST_PG_PORT
SECRETBRIDGE_TEST_PG_PORT=$(docker port "$task_pg" 5432/tcp | awk -F: '{print $NF}')
export SECRETBRIDGE_TEST_MYSQL_PORT
SECRETBRIDGE_TEST_MYSQL_PORT=$(docker port "$task_mysql" 3306/tcp | awk -F: '{print $NF}')
export SECRETBRIDGE_TEST_DB_CA="$task_tmp/ca.pem"
cargo test -p secretbridge-server database_task::tests::real_ -- --ignored
cargo test -p secretbridge-server native_mcp_executes_real_databases -- --ignored
