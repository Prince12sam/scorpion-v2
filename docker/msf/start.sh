#!/bin/bash
# msfrpcd's own default config/database.yml uses DATABASE_URL, but that hits
# a real ActiveRecord/Ruby URI-parser bug (URI::InvalidURIError: "the scheme
# postgres does not accept registry part") — ActiveRecord's
# ConnectionUrlResolver uses the old RFC2396 parser, which rejects userinfo
# for unregistered schemes regardless of "postgres" vs "postgresql". Writing
# a real database.yml with explicit fields sidesteps URI parsing entirely.
set -e
cd /usr/src/metasploit-framework

cat > config/database.yml <<YAML
production:
  adapter: postgresql
  database: ${MSF_PG_DB}
  username: ${MSF_PG_USER}
  password: ${MSF_PG_PASSWORD}
  host: msf_postgres
  port: 5432
  pool: 25
  timeout: 5
YAML

rake db:prepare
exec ./msfrpcd -U "${MSF_RPC_USER}" -P "${MSF_RPC_PASSWORD}" -a 0.0.0.0 -p 55553 -f -S
