#!/bin/sh
# Fly entrypoint for zeusi-mcp (docs/hosting.md). Runs as root ONLY to prepare the
# volume (Fly mounts it root-owned) and the run directory, then drops to the unprivileged
# `node` user and execs the authenticated hosted server. It never starts stdio or the
# loopback --http server.
#
# Write service (docs/hosting.md "Write service"): OFF unless BOTH Fly secrets are set:
#   ZEUSI_MCP_WRITE_SERVICE  service name in the service file, e.g. zeusi_decision
#   ZEUSI_DECISION_PGPASS    ONE pgpass line, host:port:dbname:zeusi_box_decision:password
# Then the line is written to $RUN_DIR/pgpass (node, 0600; never on the volume, never echoed),
# PGPASSFILE points at it and the server gets --write-service. If the service is set but the
# secret is missing or malformed, the server starts READ-ONLY with one loud log line (no value):
# reads stay available, writes stay refused (fail closed). ZEUSI_DECISION_PGPASS is removed
# from the environment before node starts, in every case.
#
# Personal workspaces (open sign-up, docs/hosting.md "Workspaces"): OFF unless BOTH secrets are set:
#   ZEUSI_TENANT_RT_PGPASS     ONE pgpass line, host:port:dbname:zeusi_tenant_rt:password
#   ZEUSI_TENANT_ADMIN_PGPASS  ONE pgpass line, host:port:dbname:zeusi_tenant_admin:password
# Then both lines are appended to $RUN_DIR/pgpass (node, 0600), PGPASSFILE points at it and the
# server gets --tenant-service zeusi_tenant_rt --tenant-admin-service zeusi_tenant_admin (service
# sections of those names must exist in the service file). One missing or malformed: sign-up stays
# off with one loud log line (no value); operator members are unaffected. Both are removed from the
# environment before node starts, in every case.
#   DIRECT HOST ONLY: [zeusi_tenant_rt] and [zeusi_tenant_admin] must name the database's DIRECT
#   endpoint (Neon: the host WITHOUT -pooler), and both pgpass lines must name that same direct
#   host. The workspace router sets the role and search_path per session; through a transaction
#   pooler that state leaks to the next client. The server refuses a -pooler workspace host at
#   startup (log line "WORKSPACE SIGN-UP OFF: ...", sign-up stays off). The team read service and
#   the decision service may stay on the pooler.
#
# Own-workspace writes (import preview/commit, nightly sync; docs/hosting.md "Workspace writes"):
# OFF unless sign-up is ON and this secret is set:
#   ZEUSI_TENANT_WR_PGPASS     ONE pgpass line, host:port:dbname:zeusi_tenant_wr:password
# Then the line is appended to $RUN_DIR/pgpass (node, 0600) and the server gets
# --tenant-writer-service zeusi_tenant_wr (a [zeusi_tenant_wr] section must exist in the service file,
# on the DIRECT host like the other workspace logins: the server refuses a -pooler host at startup,
# log line "WORKSPACE WRITES OFF: ..."). Missing or malformed: writes stay off with one loud log line
# (no value); reads and sign-up are unaffected. Removed from the environment before node starts.
#
# PGSERVICEFILE: a path is used as is. A value holding the file CONTENT (it has a newline)
# is written to $RUN_DIR/pg_service.conf (node, 0600) and PGSERVICEFILE points there.
set -eu

DATA_DIR=/data
RUN_DIR=/run/zeusi

log() { echo "fly-entrypoint: $*" >&2; }

if [ ! -d "$DATA_DIR" ]; then
  log "$DATA_DIR is not a directory (volume zeusi_data not mounted); refusing to start"
  exit 1
fi
if ! mountpoint -q "$DATA_DIR"; then
  log "$DATA_DIR is not a mount point (volume zeusi_data not mounted); refusing to start"
  exit 1
fi

chown node:node "$DATA_DIR"
chmod 700 "$DATA_DIR"

NL='
'
CR=$(printf '\r')

# Fresh run dir for materialised secrets (node-owned, 0700). Ephemeral root fs, not the volume.
umask 077
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"

# --- service file: content -> file (a path is left alone) --------------------------------
case "${PGSERVICEFILE:-}" in
  *"$NL"*)
    printf '%s\n' "$PGSERVICEFILE" > "$RUN_DIR/pg_service.conf"
    chmod 600 "$RUN_DIR/pg_service.conf"
    PGSERVICEFILE="$RUN_DIR/pg_service.conf"
    export PGSERVICEFILE
    log "service file: materialised from the PGSERVICEFILE secret (content not shown)"
    ;;
esac

# --- write service: opt-in, fail closed to read-only --------------------------------------
# Returns 0 when $1 is one well-formed pgpass line for the login $2 (a non-empty password, no CR or
# LF, no escape or empty field in host:port:dbname). Never prints the value.
pgpass_line_ok() {
  v="$1"
  want="$2"
  [ -n "$v" ] || return 1
  case "$v" in *"$NL"*|*"$CR"*) return 1 ;; esac
  rest=${v#*:}; rest=${rest#*:}; rest=${rest#*:}
  [ "$rest" != "$v" ] || return 1
  prefix=${v%"$rest"}
  case "$prefix" in *\\*|:*|*::*) return 1 ;; esac
  case "$rest" in "$want":?*) return 0 ;; esac
  return 1
}
# Returns 0 when ZEUSI_DECISION_PGPASS is one well-formed pgpass line for zeusi_box_decision.
decision_pgpass_ok() {
  pgpass_line_ok "${ZEUSI_DECISION_PGPASS:-}" zeusi_box_decision
}

WRITE=no
SVC="${ZEUSI_MCP_WRITE_SERVICE:-}"
if [ -n "$SVC" ]; then
  if [ "${#SVC}" -gt 64 ] || case "$SVC" in *[!A-Za-z0-9_-]*) true ;; *) false ;; esac; then
    log "write service REFUSED: ZEUSI_MCP_WRITE_SERVICE is not a service name (letters, digits, _ and -); starting read-only"
  elif [ -z "${ZEUSI_DECISION_PGPASS:-}" ]; then
    log "write service REFUSED: ZEUSI_MCP_WRITE_SERVICE is set but the ZEUSI_DECISION_PGPASS secret is missing; starting read-only"
  elif ! decision_pgpass_ok; then
    log "write service REFUSED: ZEUSI_DECISION_PGPASS is not one pgpass line host:port:dbname:zeusi_box_decision:password (value not shown); starting read-only"
  else
    printf '%s\n' "$ZEUSI_DECISION_PGPASS" > "$RUN_DIR/pgpass"
    chmod 600 "$RUN_DIR/pgpass"
    WRITE=yes
  fi
fi
unset ZEUSI_DECISION_PGPASS v rest prefix 2>/dev/null || true

# --- personal workspaces: opt-in, fail closed to "sign-up off" -----------------------------
TENANTS=no
if [ -n "${ZEUSI_TENANT_RT_PGPASS:-}" ] || [ -n "${ZEUSI_TENANT_ADMIN_PGPASS:-}" ]; then
  if [ -z "${ZEUSI_TENANT_RT_PGPASS:-}" ] || [ -z "${ZEUSI_TENANT_ADMIN_PGPASS:-}" ]; then
    log "workspace sign-up REFUSED: set both ZEUSI_TENANT_RT_PGPASS and ZEUSI_TENANT_ADMIN_PGPASS; sign-up stays off"
  elif ! pgpass_line_ok "$ZEUSI_TENANT_RT_PGPASS" zeusi_tenant_rt || ! pgpass_line_ok "$ZEUSI_TENANT_ADMIN_PGPASS" zeusi_tenant_admin; then
    log "workspace sign-up REFUSED: ZEUSI_TENANT_RT_PGPASS / ZEUSI_TENANT_ADMIN_PGPASS must each be one pgpass line for zeusi_tenant_rt / zeusi_tenant_admin (values not shown); sign-up stays off"
  else
    printf '%s\n%s\n' "$ZEUSI_TENANT_RT_PGPASS" "$ZEUSI_TENANT_ADMIN_PGPASS" >> "$RUN_DIR/pgpass"
    chmod 600 "$RUN_DIR/pgpass"
    TENANTS=yes
  fi
else
  log "workspace sign-up off (no tenant secrets)"
fi
unset ZEUSI_TENANT_RT_PGPASS ZEUSI_TENANT_ADMIN_PGPASS v rest prefix want 2>/dev/null || true

# --- own-workspace writes: opt-in, needs sign-up, fail closed to "writes off" ---------------------
WSWRITE=no
if [ -n "${ZEUSI_TENANT_WR_PGPASS:-}" ]; then
  if [ "$TENANTS" != yes ]; then
    log "workspace writes REFUSED: ZEUSI_TENANT_WR_PGPASS is set but workspace sign-up is off; writes stay off"
  elif ! pgpass_line_ok "$ZEUSI_TENANT_WR_PGPASS" zeusi_tenant_wr; then
    log "workspace writes REFUSED: ZEUSI_TENANT_WR_PGPASS must be one pgpass line for zeusi_tenant_wr (value not shown); writes stay off"
  else
    printf '%s\n' "$ZEUSI_TENANT_WR_PGPASS" >> "$RUN_DIR/pgpass"
    chmod 600 "$RUN_DIR/pgpass"
    WSWRITE=yes
  fi
else
  log "workspace writes off (no writer secret)"
fi
unset ZEUSI_TENANT_WR_PGPASS v rest prefix want 2>/dev/null || true

chown -R node:node "$RUN_DIR"

set -- node /app/dist/mcp.js --hosted --data-dir "$DATA_DIR"
if [ "$WRITE" = yes ]; then
  PGPASSFILE="$RUN_DIR/pgpass"
  export PGPASSFILE
  set -- "$@" --write-service "$SVC"
  log "write service ON: --write-service $SVC (password file $RUN_DIR/pgpass, 0600)"
else
  # Read-only: node must not pick the service up from the environment either.
  unset ZEUSI_MCP_WRITE_SERVICE PGPASSFILE 2>/dev/null || true
  [ -n "$SVC" ] || log "write service off (read-only)"
fi
if [ "$TENANTS" = yes ]; then
  PGPASSFILE="$RUN_DIR/pgpass"
  export PGPASSFILE
  set -- "$@" --tenant-service zeusi_tenant_rt --tenant-admin-service zeusi_tenant_admin
  log "workspace sign-up ON: --tenant-service zeusi_tenant_rt --tenant-admin-service zeusi_tenant_admin (password file $RUN_DIR/pgpass, 0600)"
fi
if [ "$WSWRITE" = yes ]; then
  set -- "$@" --tenant-writer-service zeusi_tenant_wr
  log "workspace writes ON: --tenant-writer-service zeusi_tenant_wr (password file $RUN_DIR/pgpass, 0600)"
fi

exec setpriv --reuid=node --regid=node --init-groups -- "$@"
