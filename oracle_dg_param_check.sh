#!/usr/bin/env bash
#===============================================================================
# dg_param_audit.sh
#
# Oracle Data Guard spfile parameter auditor + memory sanity checker.
#
# WHAT IT DOES
#   1. Auto-discovers running Oracle instances on the LOCAL host (via pmon
#      processes), matched against oratab for ORACLE_HOME. ASM, -MGMTDB and
#      APEX/APX-style repository instances are excluded automatically.
#   2. For every real DB instance found, connects AS SYSDBA (OS auth) and,
#      using ONLY fixed (V$) views (works on a mounted/read-only standby),
#      determines DB_NAME / DB_UNIQUE_NAME / DATABASE_ROLE / CDB status and
#      dumps every explicitly-set spfile parameter (PDB-aware, via
#      V$SPFILEPARAMETER.CON_ID + V$PDBS) to a CSV on a shared NFS location.
#   3. Because the SAME script runs unmodified on both primary and standby
#      hosts, and both write to the same NFS directory under a predictable
#      filename, the script also tries -- on every run, regardless of which
#      side it's running on -- to find the "opposite side" file for the same
#      DB_NAME and, if found, produces a parameter-mismatch CSV. If the
#      opposite side hasn't run yet, it just skips the comparison quietly
#      (this is expected, not an error).
#   4. PRIMARY ONLY: compares each instance's live (V$PARAMETER) memory
#      settings against what's persisted in the spfile (V$SPFILEPARAMETER),
#      to catch "alter system ... scope=memory" drift. It also aggregates
#      configured SGA+PGA across all instances on the node and compares that
#      to the host's physical RAM.
#   5. Renders one self-contained interactive HTML dashboard (islands per
#      database, collapsible sections, color-coded status, a JS
#      expand/collapse + filter -- degrades gracefully with JS/CSS only)
#      and e-mails it (MIME, inline summary + attached full dashboard +
#      attached raw CSVs) via sendmail (falls back to mailx).
#   6. Housekeeping: retention-based cleanup of archives/logs, stale lock
#      detection, log size capping.
#
# DESIGN NOTES / ASSUMPTIONS (please review before production use)
#   - Requires bash 3.2+ (works with the ancient bash shipped on Solaris 10/11
#     as well as any Linux bash). No associative arrays are used anywhere
#     (bash 3.2 doesn't have them) -- awk is used for all key/value work.
#   - BASE_DIR must be the same NFS-mounted path on both primary and standby
#     hosts.
#   - "Fixed views only" is used for BOTH primary and standby extraction
#     (V$DATABASE, V$INSTANCE, V$PDBS, V$PARAMETER, V$SPFILEPARAMETER) so the
#     exact same SQL works everywhere, including on a mounted standby where
#     DBA_*/CDB_* views are not usable.
#   - PDB-awareness for spfile comparison does NOT require the PDBs to be
#     open. V$SPFILEPARAMETER already carries a CON_ID for any parameter
#     that was ever set FOR PDB via ALTER SYSTEM ... SCOPE=SPFILE, so we
#     just join that CON_ID to V$PDBS.NAME. No ALTER SESSION SET CONTAINER
#     is needed (and wouldn't work on a mounted standby anyway).
#   - Size-valued parameters (sga_target etc.) are normalized (K/M/G/T ->
#     bytes) before comparison in the memory-vs-spfile check ONLY, because
#     V$PARAMETER always reports bytes while V$SPFILEPARAMETER may retain the
#     literal "512M" style string that was set. The primary-vs-standby
#     parameter comparison does NOT need this because both sides read the
#     same view the same way.
#   - "APEX"/APX exclusion: there is no dedicated pmon process for APEX (it
#     runs inside a normal DB). We assume you mean a repository/monitoring
#     instance whose SID contains "APX" (as used by some OEM/CHM style
#     agents) and exclude any pmon SID matching that pattern in addition to
#     +ASM and -MGMTDB. Adjust EXCLUDE_PMON_REGEX if this isn't right for
#     your environment.
#   - The exclusion list for "obviously different" parameters
#     (EXCLUDE_PARAMS_REGEX) is a reasonable DBA-standard starting point --
#     review and tune it for your environment before relying on the report.
#   - Node-memory sizing uses /proc/meminfo on Linux and prtconf on Solaris.
#     In a Solaris zone / LDOM this may reflect the global zone's memory, not
#     an effective cap -- treat that number as advisory only.
#   - The interactive JS (expand/collapse, filter) will not execute inside
#     an email client (most strip <script>). The <details>/<summary>
#     sections still expand/collapse in the browser with pure HTML, so the
#     report degrades gracefully; the fully interactive version is best
#     viewed via the attached dashboard file, not the inline email body.
#
# USAGE
#   Deploy this single script identically to both the primary and standby
#   hosts (same path, same BASE_DIR mounted from the same NFS share).
#   Schedule it via cron/crontab on BOTH hosts, e.g. staggered a few minutes
#   apart so the "opposite side" file usually already exists:
#       # primary host crontab
#       15 * * * * /path/to/dg_param_audit.sh >> /var/log/dg_param_audit.cron.log 2>&1
#       # standby host crontab
#       20 * * * * /path/to/dg_param_audit.sh >> /var/log/dg_param_audit.cron.log 2>&1
#
#   Override any config value via environment variables prefixed DG_AUDIT_*
#   (see CONFIGURATION block below) without editing the script, e.g.:
#       DG_AUDIT_BASE_DIR=/nfs/dba/paramaudit DG_AUDIT_EMAIL_TO=dba@corp.com \
#           /path/to/dg_param_audit.sh
#
#===============================================================================

set -u
set -o pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0.0"
RUN_TS="$(date '+%Y%m%d_%H%M%S')"
SCRIPT_START_EPOCH_HUMAN="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date)"

############################################
# ===== CONFIGURATION (env overridable) ====
############################################
BASE_DIR="${DG_AUDIT_BASE_DIR:-/nfs/dbaudit}"          # MUST be same NFS path on primary+standby
LATEST_DIR="${BASE_DIR}/latest"                         # "current truth" files, overwritten each run
ARCHIVE_DIR="${BASE_DIR}/archive"                        # timestamped history, pruned by retention
LOG_DIR="${BASE_DIR}/logs"
LOCK_DIR="${BASE_DIR}/lock"
LOCK_FILE="${LOCK_DIR}/${SCRIPT_NAME}.lock"
MAIN_LOG="${LOG_DIR}/dg_param_audit.log"
RUN_LOG="${LOG_DIR}/run_${RUN_TS}.log"
THIS_RUN_ARCHIVE="${ARCHIVE_DIR}/${RUN_TS}"

RETENTION_DAYS="${DG_AUDIT_RETENTION_DAYS:-30}"          # archive/log retention
MAIN_LOG_MAX_LINES="${DG_AUDIT_LOG_MAX_LINES:-50000}"    # rolling cap on the main log

EMAIL_TO="${DG_AUDIT_EMAIL_TO:-dba-team@example.com}"
EMAIL_FROM="${DG_AUDIT_EMAIL_FROM:-oracle@$(hostname 2>/dev/null || echo localhost)}"
EMAIL_SUBJECT_PREFIX="${DG_AUDIT_EMAIL_SUBJECT_PREFIX:-[DG Param Audit]}"
SEND_EMAIL="${DG_AUDIT_SEND_EMAIL:-1}"                   # 1=send, 0=generate report only
SENDMAIL_BIN=""

SQLPLUS_TIMEOUT="${DG_AUDIT_SQLPLUS_TIMEOUT:-120}"       # seconds, used if `timeout` binary exists

MEM_WARN_PCT="${DG_AUDIT_MEM_WARN_PCT:-85}"              # node memory usage warn threshold (%)
MEM_CRIT_PCT="${DG_AUDIT_MEM_CRIT_PCT:-100}"             # node memory usage critical threshold (%)

# pmon processes to exclude from discovery (extended regex, matched against the
# extracted SID/instance token, e.g. "+ASM1", "-MGMTDB", "APX")
EXCLUDE_PMON_REGEX="${DG_AUDIT_EXCLUDE_PMON_REGEX:-(^\+ASM)|(^-MGMTDB$)|(APX)}"

# Parameters excluded from the primary/standby comparison because they are
# expected/allowed to differ. Review and tune for your environment.
EXCLUDE_PARAMS_REGEX="${DG_AUDIT_EXCLUDE_PARAMS_REGEX:-^(instance_name|instance_number|thread|db_unique_name|service_names|local_listener|remote_listener|listener_networks|spfile|background_dump_dest|user_dump_dest|core_dump_dest|audit_file_dest|diagnostic_dest|log_archive_dest_[0-9]+|log_archive_dest_state_[0-9]+|fal_server|fal_client|dg_broker_start|dg_broker_config_file[12]|log_archive_config|standby_file_management|archive_lag_target|remote_login_passwordfile|cluster_database_instances|undo_tablespace|control_files|dispatchers|utl_file_dir|db_create_online_log_dest_[0-9]+|db_file_name_convert|log_file_name_convert)$}"

# Memory parameters checked for runtime-vs-spfile drift (primary only)
MEMORY_PARAMS="${DG_AUDIT_MEMORY_PARAMS:-sga_target sga_max_size pga_aggregate_target pga_aggregate_limit memory_target memory_max_target db_cache_size shared_pool_size large_pool_size java_pool_size streams_pool_size log_buffer}"

# Working scratch space for generated .sql files (prefer local /tmp, not NFS)
SQLDIR="${DG_AUDIT_SQLDIR:-}"

############################################
# ===== OS DETECTION / PORTABILITY =========
############################################
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
HOST_NAME="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown-host)"

case "${OS_NAME}" in
  SunOS)
    ORATAB="/var/opt/oracle/oratab"
    [ -f "${ORATAB}" ] || ORATAB="/etc/oratab"
    if command -v nawk >/dev/null 2>&1; then
      AWK_BIN="nawk"
    elif [ -x /usr/xpg4/bin/awk ]; then
      AWK_BIN="/usr/xpg4/bin/awk"
    else
      AWK_BIN="awk"
    fi
    ;;
  Linux)
    ORATAB="/etc/oratab"
    AWK_BIN="awk"
    ;;
  *)
    echo "FATAL: Unsupported OS '${OS_NAME}'. This script supports SunOS and Linux only." >&2
    exit 1
    ;;
esac

TIMEOUT_BIN=""
command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN="timeout"

# Allow override for testing / nonstandard installs
ORATAB="${DG_AUDIT_ORATAB:-${ORATAB}}"

############################################
# ===== LOGGING =============================
############################################
log() {
    local level="$1"; shift
    local msg="$*"
    local ts line
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    line="$(printf '%s [%-5s] %s' "${ts}" "${level}" "${msg}")"
    # IMPORTANT: console copy goes to STDERR, never stdout. Several functions
    # in this script (discover_instances, etc.) are invoked via command
    # substitution - "$(some_func)" - and call log() internally; if log()
    # wrote to stdout it would silently corrupt whatever that function
    # returns. Cron entries in the header use ">> file 2>&1" so nothing is
    # lost in practice.
    printf '%s\n' "${line}" >&2
    printf '%s\n' "${line}" >> "${RUN_LOG}" 2>/dev/null
    printf '%s\n' "${line}" >> "${MAIN_LOG}" 2>/dev/null
}

die() {
    log ERROR "$*"
    log ERROR "Aborting."
    exit 1
}

############################################
# ===== TEMP FILE TRACKING / CLEANUP =======
############################################
TMP_FILES=""

mk_tmp() {
    local dir="${SQLDIR:-${BASE_DIR}}"
    local t
    t="$(mktemp "${dir}/.dgaudit_tmp.XXXXXX" 2>/dev/null)" || t="$(mktemp 2>/dev/null)"
    [ -z "${t}" ] && die "mktemp failed - cannot create temp file"
    TMP_FILES="${TMP_FILES} ${t}"
    echo "${t}"
}

cleanup_tmp() {
    local f
    for f in ${TMP_FILES}; do
        [ -f "${f}" ] && rm -f "${f}" 2>/dev/null
    done
}

release_lock() {
    rm -f "${LOCK_FILE}" 2>/dev/null
}

on_exit() {
    local rc=$?
    cleanup_tmp
    release_lock
    log INFO "===== Run finished (exit code ${rc}) ====="
    exit "${rc}"
}

on_signal() {
    log ERROR "Interrupted by signal - cleaning up."
    cleanup_tmp
    release_lock
    exit 130
}

trap on_exit EXIT
trap on_signal INT TERM HUP

############################################
# ===== DIRECTORY INITIALIZATION ===========
############################################
init_dirs() {
    local d
    for d in "${BASE_DIR}" "${LATEST_DIR}" "${ARCHIVE_DIR}" "${THIS_RUN_ARCHIVE}" "${LOG_DIR}" "${LOCK_DIR}"; do
        if ! mkdir -p "${d}" 2>/dev/null; then
            echo "FATAL: cannot create directory '${d}' - check that ${BASE_DIR} (NFS share) is mounted and writable." >&2
            exit 2
        fi
    done

    local testfile="${BASE_DIR}/.write_test_$$"
    if ! ( : > "${testfile}" ) 2>/dev/null; then
        echo "FATAL: ${BASE_DIR} exists but is not writable (NFS mount read-only or permissions issue?)." >&2
        exit 2
    fi
    rm -f "${testfile}" 2>/dev/null

    if [ -z "${SQLDIR}" ]; then
        if [ -d /tmp ] && [ -w /tmp ]; then
            SQLDIR="$(mktemp -d /tmp/dgaudit_sql.XXXXXX 2>/dev/null)"
        fi
        [ -z "${SQLDIR}" ] && SQLDIR="${BASE_DIR}/.sqlwork"
        mkdir -p "${SQLDIR}" 2>/dev/null || die "cannot create SQLDIR ${SQLDIR}"
    fi
}

############################################
# ===== LOCKING (single-instance guard) ====
############################################
acquire_lock() {
    if [ -e "${LOCK_FILE}" ]; then
        local lock_pid
        lock_pid="$(cat "${LOCK_FILE}" 2>/dev/null)"
        if [ -n "${lock_pid}" ] && kill -0 "${lock_pid}" 2>/dev/null; then
            log ERROR "Another instance of ${SCRIPT_NAME} appears to be running (pid ${lock_pid}, lockfile ${LOCK_FILE}). Exiting."
            exit 3
        else
            log WARN "Stale lock file found (pid ${lock_pid:-unknown} not running). Removing and continuing."
            rm -f "${LOCK_FILE}" 2>/dev/null
        fi
    fi
    echo $$ > "${LOCK_FILE}" 2>/dev/null || die "cannot write lock file ${LOCK_FILE}"
}

############################################
# ===== PREREQUISITE CHECKS ================
############################################
check_prereqs() {
    local bin missing=0
    for bin in ps sed grep find mkdir mktemp hostname date cat cp mv wc sort tr; do
        command -v "${bin}" >/dev/null 2>&1 || { log ERROR "Required command not found in PATH: ${bin}"; missing=1; }
    done
    command -v "${AWK_BIN}" >/dev/null 2>&1 || { log ERROR "AWK binary not found/usable: ${AWK_BIN}"; missing=1; }
    [ "${missing}" -eq 1 ] && die "Missing one or more required OS utilities. See errors above."

    SENDMAIL_BIN="$(command -v sendmail 2>/dev/null || true)"
    [ -z "${SENDMAIL_BIN}" ] && [ -x /usr/sbin/sendmail ] && SENDMAIL_BIN=/usr/sbin/sendmail
    [ -z "${SENDMAIL_BIN}" ] && [ -x /usr/lib/sendmail ] && SENDMAIL_BIN=/usr/lib/sendmail
    if [ -z "${SENDMAIL_BIN}" ] && ! command -v mailx >/dev/null 2>&1 && ! command -v mail >/dev/null 2>&1; then
        log WARN "Neither sendmail nor mailx/mail found. Email sending will be skipped; report will still be generated on disk."
    fi

    if [ ! -f "${ORATAB}" ]; then
        log WARN "oratab not found at ${ORATAB}. Instances not listed there will be skipped."
    fi
}

sanitize() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

############################################
# ===== SQL SCRIPT GENERATION ==============
# All queries use ONLY fixed (V$) views so the identical SQL works on a
# mounted/read-only standby as well as an open primary. Heredocs below use a
# QUOTED delimiter ('SQL_EOF') so bash does NOT try to expand the many '$'
# characters in V$DATABASE / V$INSTANCE / V$PDBS / V$PARAMETER /
# V$SPFILEPARAMETER as shell variables - this is a classic bug in
# hand-rolled Oracle wrapper scripts and is deliberately avoided here.
############################################
write_sql_scripts() {
    cat > "${SQLDIR}/dbinfo.sql" <<'SQL_EOF'
WHENEVER SQLERROR EXIT 1
WHENEVER OSERROR EXIT 9
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF TERMOUT OFF TRIMSPOOL ON LINESIZE 2000
CONNECT / AS SYSDBA
SELECT 'DBINFO|'||d.NAME||'|'||d.DB_UNIQUE_NAME||'|'||d.DATABASE_ROLE||'|'||d.OPEN_MODE||'|'||d.CDB||'|'||i.INSTANCE_NAME||'|'||i.HOST_NAME||'|'||i.STATUS
FROM V$DATABASE d, V$INSTANCE i;
EXIT SUCCESS
SQL_EOF

    cat > "${SQLDIR}/spparams.sql" <<'SQL_EOF'
WHENEVER SQLERROR EXIT 1
WHENEVER OSERROR EXIT 9
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF TERMOUT OFF TRIMSPOOL ON LINESIZE 4000 LONG 2000000
CONNECT / AS SYSDBA
SELECT 'PARAM|'||NVL(p.CON_ID,0)||'|'||NVL((SELECT pd.NAME FROM V$PDBS pd WHERE pd.CON_ID = p.CON_ID),'CDB$ROOT')||'|'||p.NAME||'|'||REPLACE(REPLACE(p.VALUE,CHR(10),' '),'|',';')||'|'||p.ORDINAL
FROM V$SPFILEPARAMETER p
WHERE p.ISSPECIFIED = 'TRUE'
ORDER BY 2,3,5;
EXIT SUCCESS
SQL_EOF

    # memcheck.sql is generated dynamically per-run below (build_memcheck_sql)
    # because the parameter IN-list comes from the MEMORY_PARAMS config value.
    return 0
}

build_memcheck_sql() {
    local p list=""
    for p in ${MEMORY_PARAMS}; do
        if [ -z "${list}" ]; then
            list="'${p}'"
        else
            list="${list},'${p}'"
        fi
    done

    {
        printf 'WHENEVER SQLERROR EXIT 1\n'
        printf 'WHENEVER OSERROR EXIT 9\n'
        printf 'SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF TERMOUT OFF TRIMSPOOL ON LINESIZE 4000\n'
        printf 'CONNECT / AS SYSDBA\n'
        printf "SELECT 'MEMCHK|'||cp.NAME||'|'||cp.VALUE||'|'||NVL(sp.VALUE,'__NOTSET__')\n"
        printf 'FROM V$PARAMETER cp\n'
        printf 'LEFT JOIN V$SPFILEPARAMETER sp ON sp.NAME = cp.NAME AND NVL(sp.CON_ID,0) = 0\n'
        printf 'WHERE cp.CON_ID = 0\n'
        printf "AND cp.NAME IN (%s)\n" "${list}"
        printf 'ORDER BY 1;\n'
        printf 'EXIT SUCCESS\n'
    } > "${SQLDIR}/memcheck.sql"
}

############################################
# ===== SQL*Plus RUNNER ====================
############################################
run_sqlplus_script() {
    # run_sqlplus_script <sqlfile> <outfile>
    local sqlfile="$1" outfile="$2"
    : > "${outfile}"
    if [ -n "${TIMEOUT_BIN}" ]; then
        "${TIMEOUT_BIN}" "${SQLPLUS_TIMEOUT}" sqlplus -s /nolog < "${sqlfile}" > "${outfile}" 2>&1
    else
        sqlplus -s /nolog < "${sqlfile}" > "${outfile}" 2>&1
    fi
    return $?
}

############################################
# ===== ORATAB LOOKUP ======================
############################################
get_oracle_home() {
    local sid="$1"
    "${AWK_BIN}" -F: -v s="${sid}" \
        '$0 !~ /^#/ && $0 !~ /^[[:space:]]*$/ && $1 == s { print $2; exit }' \
        "${ORATAB}" 2>/dev/null
}

############################################
# ===== INSTANCE DISCOVERY (pmon scan) =====
# Excludes ASM, -MGMTDB and APX/APEX-repository style SIDs per
# EXCLUDE_PMON_REGEX. Only SIDs that are also present in oratab (i.e. have a
# valid ORACLE_HOME) are considered - this also naturally skips things like
# ASM/GI-only processes that some sites don't list in oratab at all.
############################################
discover_instances() {
    ps -ef 2>/dev/null | grep -E '(ora|asm)_pmon_' | grep -v grep | while IFS= read -r line; do
        sid="$(printf '%s\n' "${line}" | "${AWK_BIN}" '{print $NF}')"
        sid="$(printf '%s' "${sid}" | sed -n 's/.*_pmon_//p')"
        [ -z "${sid}" ] && continue
        if printf '%s' "${sid}" | grep -E -q "${EXCLUDE_PMON_REGEX}"; then
            log INFO "Discovery: excluding '${sid}' (matches EXCLUDE_PMON_REGEX)"
            continue
        fi
        printf '%s\n' "${sid}"
    done | sort -u
}

############################################
# ===== RUN STATE (bash 3.2 safe - plain files, not assoc arrays) =========
# We track "what did we learn this run" in plain text files under SQLDIR so
# later stages (compare / memory / node-memory / html) can read it back
# without relying on bash 4 associative arrays.
############################################
DBNAMES_SEEN_FILE=""     # one dbname per line, de-duped
INSTANCE_MEM_FILE=""     # host|sid|dbuname|sga_bytes|pga_bytes  (primary only)
DBINFO_SUMMARY_FILE=""   # dbname|dbuname|role|openmode|cdb|instance|host|status

init_run_state() {
    DBNAMES_SEEN_FILE="$(mk_tmp)"
    INSTANCE_MEM_FILE="$(mk_tmp)"
    DBINFO_SUMMARY_FILE="$(mk_tmp)"
    : > "${DBNAMES_SEEN_FILE}"
    : > "${INSTANCE_MEM_FILE}"
    : > "${DBINFO_SUMMARY_FILE}"
}

############################################
# ===== SIZE NORMALIZATION (for memory compare only) =======================
############################################
# Implemented as an awk snippet re-used by build-time inline programs; see
# normalize_size() usage inside compute_memory_vs_spfile().
NORMALIZE_AWK_FUNC='
function normsize(v,   num, unit, mult) {
    if (v ~ /^[0-9]+[KkMmGgTt]$/) {
        num = v
        sub(/[KkMmGgTt]$/, "", num)
        unit = toupper(substr(v, length(v), 1))
        if (unit == "K") mult = 1024
        else if (unit == "M") mult = 1024*1024
        else if (unit == "G") mult = 1024*1024*1024
        else if (unit == "T") mult = 1024*1024*1024*1024
        else mult = 1
        return num * mult
    }
    return v
}
'

############################################
# ===== REMOVE STALE OPPOSITE-ROLE FILE ====
# If a db_unique_name flips role (switchover), stop stale opposite-role
# files from confusing the comparison step.
############################################
purge_stale_role_files() {
    local dbn="$1" dbu="$2" role="$3"
    local other="STANDBY"
    [ "${role}" = "STANDBY" ] && other="PRIMARY"
    local pat="${LATEST_DIR}/${dbn}__${dbu}__${other}"
    rm -f "${pat}.spfile.csv" "${pat}.spfile.raw" 2>/dev/null
}

############################################
# ===== PER-INSTANCE PROCESSING ============
############################################
process_instance() {
    local sid="$1"
    local ohome
    ohome="$(get_oracle_home "${sid}")"
    if [ -z "${ohome}" ]; then
        log WARN "SID ${sid} is running but has no entry in ${ORATAB}; skipping."
        return 1
    fi
    if [ ! -x "${ohome}/bin/sqlplus" ]; then
        log WARN "sqlplus not executable under ORACLE_HOME=${ohome} for SID ${sid}; skipping."
        return 1
    fi

    export ORACLE_SID="${sid}"
    export ORACLE_HOME="${ohome}"
    export PATH="${ORACLE_HOME}/bin:${PATH}"
    export LD_LIBRARY_PATH="${ORACLE_HOME}/lib:${LD_LIBRARY_PATH:-}"
    export TNS_ADMIN="${ORACLE_HOME}/network/admin"

    log INFO "Processing SID=${sid} ORACLE_HOME=${ohome}"

    local dbinfo_out
    dbinfo_out="$(mk_tmp)"
    if ! run_sqlplus_script "${SQLDIR}/dbinfo.sql" "${dbinfo_out}"; then
        log WARN "SID ${sid}: dbinfo.sql returned non-zero exit; see ${dbinfo_out} for details. Skipping instance."
        log WARN "SID ${sid}: sqlplus output was: $(tr '\n' ' ' < "${dbinfo_out}" | cut -c1-300)"
        return 1
    fi

    local line
    line="$(grep '^DBINFO|' "${dbinfo_out}" | head -1)"
    if [ -z "${line}" ]; then
        log WARN "SID ${sid}: could not retrieve V\$DATABASE/V\$INSTANCE row (instance may be in NOMOUNT, or connect failed). Skipping."
        return 1
    fi

    local _dbinfo_tag dbname dbuname role openmode cdb instname hostname_col status
    IFS='|' read -r _dbinfo_tag dbname dbuname role openmode cdb instname hostname_col status <<EOF2
${line}
EOF2

    if [ -z "${dbname}" ] || [ -z "${dbuname}" ] || [ -z "${role}" ]; then
        log WARN "SID ${sid}: DBINFO row incomplete/unparseable ('${line}'). Skipping."
        return 1
    fi

    role="$(printf '%s' "${role}" | tr '[:lower:]' '[:upper:]')"
    case "${role}" in
        PRIMARY) role_norm="PRIMARY" ;;
        *STANDBY*) role_norm="STANDBY" ;;
        *)
            log WARN "SID ${sid}: unexpected DATABASE_ROLE '${role}' (not PRIMARY/*STANDBY*) - skipping param audit for this instance, but noting it."
            role_norm="OTHER"
            ;;
    esac

    local dbn_s dbu_s
    dbn_s="$(sanitize "${dbname}")"
    dbu_s="$(sanitize "${dbuname}")"

    printf '%s\n' "${dbname}" >> "${DBNAMES_SEEN_FILE}"
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "${dbname}" "${dbuname}" "${role_norm}" "${openmode}" "${cdb}" "${instname}" "${hostname_col}" "${status}" >> "${DBINFO_SUMMARY_FILE}"

    if [ "${role_norm}" = "OTHER" ]; then
        return 0
    fi

    # ---- Part 1: spfile parameter extraction (works for PRIMARY and STANDBY) ----
    local params_out
    params_out="$(mk_tmp)"
    if ! run_sqlplus_script "${SQLDIR}/spparams.sql" "${params_out}"; then
        log WARN "SID ${sid}: spparams.sql failed; see log. Skipping parameter extraction for this instance."
    else
        purge_stale_role_files "${dbn_s}" "${dbu_s}" "${role_norm}"
        local csv_file="${LATEST_DIR}/${dbn_s}__${dbu_s}__${role_norm}.spfile.csv"
        local raw_file="${LATEST_DIR}/${dbn_s}__${dbu_s}__${role_norm}.spfile.raw"

        grep '^PARAM|' "${params_out}" | cut -d'|' -f2-6 > "${raw_file}"

        {
            echo "CON_ID,PDB_NAME,PARAMETER_NAME,VALUE,ORDINAL"
            "${AWK_BIN}" -F'|' 'BEGIN{OFS=","}
                {
                    for (i = 1; i <= NF; i++) { gsub(/"/, "\"\"", $i); $i = "\"" $i "\"" }
                    print $1,$2,$3,$4,$5
                }' "${raw_file}"
        } > "${csv_file}"

        local pcount
        pcount="$(wc -l < "${raw_file}" | tr -d ' ')"
        log INFO "SID ${sid} (${role_norm}): ${pcount} explicit spfile parameters written to ${csv_file}"

        cp -f "${csv_file}" "${THIS_RUN_ARCHIVE}/" 2>/dev/null
        cp -f "${raw_file}" "${THIS_RUN_ARCHIVE}/" 2>/dev/null
    fi

    # ---- Part 2: memory vs spfile + node memory data collection (PRIMARY only) ----
    if [ "${role_norm}" = "PRIMARY" ]; then
        compute_memory_vs_spfile "${sid}" "${dbn_s}" "${dbu_s}" "${hostname_col}"
    fi

    return 0
}

############################################
# ===== PART 2a: MEMORY (live) vs SPFILE (persisted), PRIMARY only ========
############################################
compute_memory_vs_spfile() {
    local sid="$1" dbn_s="$2" dbu_s="$3" hostname_col="$4"
    build_memcheck_sql

    local mem_out
    mem_out="$(mk_tmp)"
    if ! run_sqlplus_script "${SQLDIR}/memcheck.sql" "${mem_out}"; then
        log WARN "SID ${sid}: memcheck.sql failed; skipping memory-vs-spfile check for this instance."
        return 1
    fi

    local csv_file="${LATEST_DIR}/${dbu_s}.memory_vs_spfile.csv"
    {
        echo "PARAMETER_NAME,LIVE_VALUE,SPFILE_VALUE,STATUS"
        grep '^MEMCHK|' "${mem_out}" | "${AWK_BIN}" -F'|' -v OFS=',' "${NORMALIZE_AWK_FUNC}"'
            {
                pname = $2; live = $3; sp = $4
                sp_disp = (sp == "__NOTSET__") ? "<NOT SET IN SPFILE>" : sp
                nlive = normsize(live)
                nsp   = (sp == "__NOTSET__") ? "__NOTSET__" : normsize(sp)
                if (sp == "__NOTSET__") {
                    status = "NOT_IN_SPFILE"
                } else if (nlive == nsp) {
                    status = "OK"
                } else {
                    status = "DRIFT"
                }
                gsub(/"/,"\"\"",pname); gsub(/"/,"\"\"",live); gsub(/"/,"\"\"",sp_disp)
                printf "\"%s\",\"%s\",\"%s\",\"%s\"\n", pname, live, sp_disp, status
            }'
    } > "${csv_file}"

    local drift_count
    drift_count="$("${AWK_BIN}" '/"DRIFT"/{c++} END{print c+0}' "${csv_file}" 2>/dev/null)"
    [ -z "${drift_count}" ] && drift_count=0
    if [ "${drift_count}" -gt 0 ]; then
        log WARN "SID ${sid}: ${drift_count} memory parameter(s) differ between running instance and spfile (see ${csv_file})"
    else
        log INFO "SID ${sid}: no live-vs-spfile memory drift detected"
    fi
    cp -f "${csv_file}" "${THIS_RUN_ARCHIVE}/" 2>/dev/null

    # ---- collect this instance's configured memory footprint for node-level rollup ----
    local sga_val
    sga_val="$("${AWK_BIN}" -F',' 'NR>1 { gsub(/"/,""); if ($1=="sga_max_size" && $2!="0") print $2 }' "${csv_file}" | head -1)"
    [ -z "${sga_val}" ] && sga_val="$("${AWK_BIN}" -F',' 'NR>1 { gsub(/"/,""); if ($1=="sga_target" && $2!="0") print $2 }' "${csv_file}" | head -1)"
    [ -z "${sga_val}" ] && sga_val="$("${AWK_BIN}" -F',' 'NR>1 { gsub(/"/,""); if ($1=="memory_max_target" && $2!="0") print $2 }' "${csv_file}" | head -1)"
    [ -z "${sga_val}" ] && sga_val=0

    local pga_val2
    pga_val2="$("${AWK_BIN}" -F',' 'NR>1 { gsub(/"/,""); if ($1=="pga_aggregate_limit" && $2!="0") print $2 }' "${csv_file}" | head -1)"
    [ -z "${pga_val2}" ] && pga_val2="$("${AWK_BIN}" -F',' 'NR>1 { gsub(/"/,""); if ($1=="pga_aggregate_target" && $2!="0") print $2 }' "${csv_file}" | head -1)"
    [ -z "${pga_val2}" ] && pga_val2=0

    printf '%s|%s|%s|%s|%s\n' "${hostname_col}" "${sid}" "${dbu_s}" "${sga_val}" "${pga_val2}" >> "${INSTANCE_MEM_FILE}"
}

############################################
# ===== PART 2b: NODE PHYSICAL MEMORY ======
############################################
get_host_mem_bytes() {
    case "${OS_NAME}" in
        Linux)
            "${AWK_BIN}" '/MemTotal/ { printf "%.0f", $2*1024 }' /proc/meminfo 2>/dev/null
            ;;
        SunOS)
            /usr/sbin/prtconf 2>/dev/null | "${AWK_BIN}" '
                /Memory size:/ {
                    val=""
                    for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) val=$i
                    if ($0 ~ /Gigabytes/) printf "%.0f", val*1024*1024*1024
                    else if ($0 ~ /Megabytes/) printf "%.0f", val*1024*1024
                    else printf "%.0f", val
                }'
            ;;
        *)
            echo 0
            ;;
    esac
}

compute_node_memory_summary() {
    local host_s
    host_s="$(sanitize "${HOST_NAME}")"
    local phys_bytes
    phys_bytes="$(get_host_mem_bytes)"
    [ -z "${phys_bytes}" ] && phys_bytes=0

    local csv_file="${LATEST_DIR}/host__${host_s}.node_memory.csv"

    if [ ! -s "${INSTANCE_MEM_FILE}" ]; then
        log INFO "No primary instances found on this host this run; node memory summary not (re)written."
        return 0
    fi

    {
        echo "HOST,DB_UNIQUE_NAME,SID,CONFIGURED_SGA_BYTES,CONFIGURED_PGA_BYTES"
        "${AWK_BIN}" -F'|' -v OFS=',' -v h="${HOST_NAME}" "${NORMALIZE_AWK_FUNC}"'
            {
                sga = normsize($4); pga = normsize($5)
                printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", h, $3, $2, sga, pga
            }' "${INSTANCE_MEM_FILE}"
    } > "${csv_file}"

    local total_sga total_pga
    total_sga="$("${AWK_BIN}" -F',' 'NR>1{gsub(/"/,"");s+=$4} END{printf "%.0f", s+0}' "${csv_file}")"
    total_pga="$("${AWK_BIN}" -F',' 'NR>1{gsub(/"/,"");s+=$5} END{printf "%.0f", s+0}' "${csv_file}")"
    local total_configured=$(( total_sga + total_pga ))

    local pct=0
    if [ "${phys_bytes}" -gt 0 ] 2>/dev/null; then
        pct="$("${AWK_BIN}" -v c="${total_configured}" -v p="${phys_bytes}" 'BEGIN{ if (p>0) printf "%.1f", (c/p)*100; else print 0 }')"
    fi

    local status="OK"
    "${AWK_BIN}" -v pct="${pct}" -v warn="${MEM_WARN_PCT}" -v crit="${MEM_CRIT_PCT}" \
        'BEGIN{ if (pct+0 >= crit+0) exit 2; else if (pct+0 >= warn+0) exit 1; else exit 0 }'
    case $? in
        2) status="CRITICAL" ;;
        1) status="WARNING" ;;
        *) status="OK" ;;
    esac

    {
        echo ""
        echo "SUMMARY,,,,"
        printf '"HOST_PHYSICAL_BYTES","%s",,,\n' "${phys_bytes}"
        printf '"TOTAL_CONFIGURED_BYTES","%s",,,\n' "${total_configured}"
        printf '"PCT_OF_PHYSICAL","%s",,,\n' "${pct}"
        printf '"STATUS","%s",,,\n' "${status}"
    } >> "${csv_file}"

    log INFO "Node memory summary for ${HOST_NAME}: configured=${total_configured} bytes, physical=${phys_bytes} bytes, ${pct}% (${status})"
    cp -f "${csv_file}" "${THIS_RUN_ARCHIVE}/" 2>/dev/null
}

############################################
# ===== PART 1b: PRIMARY vs STANDBY COMPARISON =============================
# Runs regardless of which side (primary or standby) this invocation is on.
# Looks for the "opposite side" file already sitting in LATEST_DIR (written
# by a prior/other-host run of this same script). If not found yet, this is
# NOT an error - it just means the other side hasn't run yet.
############################################
compare_db() {
    local dbn_s="$1"

    local primfiles standbyfiles
    primfiles="$(ls "${LATEST_DIR}/${dbn_s}__"*"__PRIMARY.spfile.raw" 2>/dev/null)"
    standbyfiles="$(ls "${LATEST_DIR}/${dbn_s}__"*"__STANDBY.spfile.raw" 2>/dev/null)"

    if [ -z "${primfiles}" ] || [ -z "${standbyfiles}" ]; then
        log INFO "DB '${dbn_s}': comparison skipped - primary and/or standby extraction not yet available on ${LATEST_DIR}."
        return 0
    fi

    local pfile
    pfile="$(printf '%s\n' "${primfiles}" | head -1)"
    if [ "$(printf '%s\n' "${primfiles}" | wc -l | tr -d ' ')" -gt 1 ]; then
        log WARN "DB '${dbn_s}': more than one PRIMARY raw file matched; using most recently modified."
        # shellcheck disable=SC2086
        pfile="$(ls -t ${primfiles} | head -1)"
    fi

    local mismatch_csv="${LATEST_DIR}/${dbn_s}.mismatch.csv"
    local mismatch_tmp
    mismatch_tmp="$(mk_tmp)"
    echo "DB_NAME,STANDBY_DB_UNIQUE_NAME,PDB_NAME,PARAMETER_NAME,PRIMARY_VALUE,STANDBY_VALUE" > "${mismatch_tmp}"

    local sfile sdbu
    for sfile in ${standbyfiles}; do
        sdbu="$(basename "${sfile}" | "${AWK_BIN}" -F'__' '{print $2}')"
        "${AWK_BIN}" -F'|' -v excl="${EXCLUDE_PARAMS_REGEX}" -v dbn="${dbn_s}" -v sdbu="${sdbu}" '
            FNR==NR { pkey=$2"|"$3; pval[pkey]=$4; pseen[pkey]=1; next }
            { skey=$2"|"$3; sval[skey]=$4; sseen[skey]=1 }
            END {
                for (k in pseen) allk[k]=1
                for (k in sseen) allk[k]=1
                for (k in allk) {
                    n = split(k, parts, "|")
                    pdbn = parts[1]; pname = parts[2]
                    if (pname ~ excl) continue
                    pv = (k in pval) ? pval[k] : "<NOT SET>"
                    sv = (k in sval) ? sval[k] : "<NOT SET>"
                    if (pv != sv) {
                        gsub(/"/,"\"\"",pv); gsub(/"/,"\"\"",sv); gsub(/"/,"\"\"",pdbn); gsub(/"/,"\"\"",pname)
                        printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", dbn, sdbu, pdbn, pname, pv, sv
                    }
                }
            }
        ' "${pfile}" "${sfile}" >> "${mismatch_tmp}"
    done

    mv -f "${mismatch_tmp}" "${mismatch_csv}"
    local cnt
    cnt="$(( $(wc -l < "${mismatch_csv}" | tr -d ' ') - 1 ))"
    log INFO "DB '${dbn_s}': parameter comparison complete - ${cnt} mismatch row(s) written to ${mismatch_csv}"
    cp -f "${mismatch_csv}" "${THIS_RUN_ARCHIVE}/" 2>/dev/null
}

############################################
# ===== CSV -> HTML TABLE HELPER ===========
# Turns a (quoted) CSV with a header row into <table> markup. Uses awk with
# a tiny state machine that respects double-quoted fields containing commas,
# so it is safe even though we already avoid this problem by keeping raw
# pipe files for joins - this is purely for pretty rendering of the *.csv
# report files.
############################################
csv_to_html_rows() {
    local csv="$1" rowclass_field="${2:-}"   # optional column NAME to color-code on (e.g. STATUS)
    [ -f "${csv}" ] || return 0
    "${AWK_BIN}" -v rc_field="${rowclass_field}" '
        function parse_csv(line,    n, i, c, infield, cur, out, arr) {
            n = length(line); infield = 0; cur = ""; delete arr; c = 0
            for (i = 1; i <= n; i++) {
                ch = substr(line, i, 1)
                if (ch == "\"") {
                    if (infield && substr(line, i+1, 1) == "\"") { cur = cur "\""; i++ }
                    else infield = !infield
                } else if (ch == "," && !infield) {
                    c++; arr[c] = cur; cur = ""
                } else {
                    cur = cur ch
                }
            }
            c++; arr[c] = cur
            return c
        }
        NR == 1 {
            ncols = parse_csv($0)
            printf "<tr>"
            for (i = 1; i <= ncols; i++) {
                printf "<th>%s</th>", arr[i]
                if (arr[i] == rc_field) rc_col = i
            }
            printf "</tr>\n"
            next
        }
        {
            ncols = parse_csv($0)
            cls = ""
            if (rc_field == "__ALLBAD__") {
                cls = "row-bad"
            } else if (rc_col > 0) {
                v = arr[rc_col]
                if (v == "DRIFT" || v == "CRITICAL")      cls = "row-bad"
                else if (v == "WARNING" || v == "NOT_IN_SPFILE") cls = "row-warn"
                else if (v == "OK")                        cls = "row-ok"
            }
            printf "<tr class=\"%s\">", cls
            for (i = 1; i <= ncols; i++) {
                printf "<td>%s</td>", arr[i]
            }
            printf "</tr>\n"
        }
    ' "${csv}"
}

csv_row_count() {
    [ -f "$1" ] || { echo 0; return; }
    local n
    n="$(wc -l < "$1" | tr -d ' ')"
    [ "${n}" -gt 0 ] && n=$(( n - 1 ))
    echo "${n}"
}

############################################
# ===== HTML DASHBOARD GENERATION ==========
############################################
generate_html_report() {
    local html_file="$1"
    local dbnames_unique
    dbnames_unique="$(sort -u "${DBNAMES_SEEN_FILE}" 2>/dev/null)"

    # Also pick up dbnames known only from prior runs (files already sitting
    # in LATEST_DIR) so the dashboard reflects the full current state, not
    # just whatever this particular invocation touched.
    local existing_dbnames
    existing_dbnames="$(ls "${LATEST_DIR}"/*.spfile.raw 2>/dev/null | "${AWK_BIN}" -F'/' '{print $NF}' | "${AWK_BIN}" -F'__' '{print $1}' | sort -u)"
    local all_dbnames
    all_dbnames="$(printf '%s\n%s\n' "$(for d in ${dbnames_unique}; do sanitize "${d}"; done)" "${existing_dbnames}" | sed '/^$/d' | sort -u)"

    local total_mismatch=0 total_drift=0 total_node_warn=0 db_count=0

    {
        cat <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Oracle Data Guard Parameter Audit Dashboard</title>
<style>
  :root {
    --bg: #0f172a; --card-bg: #ffffff; --accent: #6366f1; --accent2: #06b6d4;
    --ok: #16a34a; --ok-bg: #dcfce7; --warn: #d97706; --warn-bg: #fef3c7;
    --bad: #dc2626; --bad-bg: #fee2e2; --text: #1e293b; --muted: #64748b;
    --border: #e2e8f0;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: linear-gradient(180deg, #0f172a 0%, #1e293b 260px, #f1f5f9 260px, #f1f5f9 100%);
    color: var(--text); padding-bottom: 60px;
  }
  header.top {
    padding: 32px 40px 20px 40px; color: #fff;
  }
  header.top h1 { margin: 0 0 6px 0; font-size: 26px; font-weight: 700; letter-spacing: .3px; }
  header.top p { margin: 0; color: #cbd5e1; font-size: 13px; }
  .summary-strip {
    display: flex; gap: 16px; flex-wrap: wrap; padding: 0 40px; margin-top: 22px;
  }
  .stat-card {
    background: var(--card-bg); border-radius: 14px; padding: 18px 22px; min-width: 170px;
    box-shadow: 0 10px 25px -8px rgba(0,0,0,0.25); flex: 1;
  }
  .stat-card .num { font-size: 30px; font-weight: 800; }
  .stat-card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; margin-top: 2px;}
  .stat-card.ok .num { color: var(--ok); }
  .stat-card.warn .num { color: var(--warn); }
  .stat-card.bad .num { color: var(--bad); }
  .stat-card.info .num { color: var(--accent); }

  .toolbar {
    padding: 22px 40px 0 40px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
  }
  .toolbar input[type=text] {
    padding: 9px 14px; border-radius: 999px; border: 1px solid var(--border); width: 260px;
    font-size: 13px;
  }
  .toolbar button {
    padding: 9px 16px; border-radius: 999px; border: none; background: var(--accent); color: #fff;
    font-size: 13px; cursor: pointer; font-weight: 600;
  }
  .toolbar button.secondary { background: #fff; color: var(--accent); border: 1px solid var(--accent); }
  .toolbar .hint { font-size: 12px; color: var(--muted); margin-left: auto; }

  main { padding: 24px 40px 40px 40px; }
  .island {
    background: var(--card-bg); border-radius: 16px; margin-bottom: 22px; overflow: hidden;
    box-shadow: 0 6px 18px -8px rgba(0,0,0,0.15); border: 1px solid var(--border);
  }
  .island > summary {
    list-style: none; cursor: pointer; padding: 18px 24px; display: flex; align-items: center;
    gap: 14px; background: linear-gradient(90deg, #eef2ff, #ecfeff);
  }
  .island > summary::-webkit-details-marker { display: none; }
  .island > summary .chev { transition: transform .15s ease; color: var(--accent); font-weight: 700; }
  .island[open] > summary .chev { transform: rotate(90deg); }
  .island summary .dbname { font-size: 17px; font-weight: 700; }
  .island summary .badge { font-size: 11px; padding: 3px 10px; border-radius: 999px; font-weight: 700; text-transform: uppercase; letter-spacing: .4px;}
  .badge.ok { background: var(--ok-bg); color: var(--ok); }
  .badge.warn { background: var(--warn-bg); color: var(--warn); }
  .badge.bad { background: var(--bad-bg); color: var(--bad); }
  .badge.info { background: #e0e7ff; color: var(--accent); }
  .island summary .meta { color: var(--muted); font-size: 12.5px; margin-left: auto; }

  .island .body { padding: 6px 24px 22px 24px; }
  section.subsection { margin-top: 16px; }
  section.subsection h3 {
    font-size: 13.5px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted);
    margin: 0 0 8px 0; display:flex; align-items:center; gap:8px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th {
    text-align: left; background: #f8fafc; color: var(--muted); font-weight: 700; padding: 8px 10px;
    border-bottom: 2px solid var(--border); position: sticky; top: 0;
  }
  tbody td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-word;}
  tbody tr:hover { background: #f8fafc; }
  tr.row-bad td { background: var(--bad-bg); }
  tr.row-warn td { background: var(--warn-bg); }
  tr.row-ok td { background: var(--ok-bg); }
  .empty-note { color: var(--muted); font-size: 13px; font-style: italic; padding: 10px 0; }
  .pending-note { color: var(--warn); font-size: 13px; font-style: italic; padding: 10px 0; }

  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 30px 0 10px 0; }
  .filter-hidden { display: none !important; }
</style>
</head>
<body>
HTML_HEAD

        printf '<header class="top"><h1>Oracle Data Guard Parameter Audit</h1><p>Generated %s on host <b>%s</b> &middot; %s v%s</p></header>\n' \
            "$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date)" "${HOST_NAME}" "${SCRIPT_NAME}" "${SCRIPT_VERSION}"

        echo '<div class="summary-strip" id="summary-strip"></div>'
        echo '<div class="toolbar">'
        echo '  <input type="text" id="filterBox" placeholder="Filter by parameter / DB name..." onkeyup="applyFilter()">'
        echo '  <button onclick="expandAll()">Expand all</button>'
        echo '  <button class="secondary" onclick="collapseAll()">Collapse all</button>'
        echo '  <span class="hint">Tip: this dashboard is best viewed as the attached file in a browser (interactivity is stripped by most email clients)</span>'
        echo '</div>'
        echo '<main id="main-content">'

        local dbn
        for dbn in ${all_dbnames}; do
            [ -z "${dbn}" ] && continue
            db_count=$(( db_count + 1 ))

            local prim_csv standby_csv_list mismatch_csv
            prim_csv="$(ls "${LATEST_DIR}/${dbn}__"*"__PRIMARY.spfile.csv" 2>/dev/null | head -1)"
            standby_csv_list="$(ls "${LATEST_DIR}/${dbn}__"*"__STANDBY.spfile.csv" 2>/dev/null)"
            mismatch_csv="${LATEST_DIR}/${dbn}.mismatch.csv"

            local prim_dbu=""
            if [ -n "${prim_csv}" ]; then
                prim_dbu="$(basename "${prim_csv}" | "${AWK_BIN}" -F'__' '{print $2}')"
            fi

            local mismatch_count=0
            [ -f "${mismatch_csv}" ] && mismatch_count="$(csv_row_count "${mismatch_csv}")"
            total_mismatch=$(( total_mismatch + mismatch_count ))

            local badge_class="info" badge_text="INFO"
            if [ -z "${prim_csv}" ] || [ -z "${standby_csv_list}" ]; then
                badge_class="warn"; badge_text="AWAITING PEER"
            elif [ "${mismatch_count}" -gt 0 ]; then
                badge_class="bad"; badge_text="${mismatch_count} MISMATCH"
            else
                badge_class="ok"; badge_text="IN SYNC"
            fi

            printf '<details class="island" open data-dbname="%s">\n' "${dbn}"
            printf '  <summary><span class="chev">&#9656;</span><span class="dbname">%s</span>' "${dbn}"
            printf '<span class="badge %s">%s</span>' "${badge_class}" "${badge_text}"
            printf '<span class="meta">primary: %s%s</span></summary>\n' \
                "${prim_dbu:-unknown}" \
                "$( [ -n "${standby_csv_list}" ] && echo " &middot; standby(s) present" || echo " &middot; no standby data yet" )"
            echo '  <div class="body">'

            echo '    <section class="subsection"><h3>Primary vs Standby Parameter Mismatches</h3>'
            if [ -z "${prim_csv}" ] || [ -z "${standby_csv_list}" ]; then
                echo '<p class="pending-note">Waiting for both primary and standby extractions to be present before comparing.</p>'
            elif [ "${mismatch_count}" -eq 0 ]; then
                echo '<p class="empty-note">No mismatches - all comparable parameters match.</p>'
            else
                echo '<table class="filter-table"><thead></thead><tbody>'
                csv_to_html_rows "${mismatch_csv}" "__ALLBAD__"
                echo '</tbody></table>'
            fi
            echo '    </section>'

            local memcsv_path
            memcsv_path="$(ls "${LATEST_DIR}/${prim_dbu}.memory_vs_spfile.csv" 2>/dev/null | head -1)"
            if [ -n "${prim_dbu}" ] && [ -f "${memcsv_path}" ]; then
                local dcount
                dcount="$("${AWK_BIN}" -F',' 'NR>1 && $0 ~ /"DRIFT"/{c++} END{print c+0}' "${memcsv_path}")"
                total_drift=$(( total_drift + dcount ))
                echo '    <section class="subsection"><h3>Primary: Live Memory vs SPFILE (drift detection)</h3>'
                echo '<table class="filter-table"><thead></thead><tbody>'
                csv_to_html_rows "${memcsv_path}" "STATUS"
                echo '</tbody></table>'
                echo '    </section>'
            fi

            echo '  </div>'
            echo '</details>'
        done

        # Node memory summary (host-level, may cover multiple DBs)
        local nodefiles
        nodefiles="$(ls "${LATEST_DIR}"/host__*.node_memory.csv 2>/dev/null)"
        if [ -n "${nodefiles}" ]; then
            echo '<details class="island" open>'
            echo '  <summary><span class="chev">&#9656;</span><span class="dbname">Node Memory Sizing</span><span class="badge info">HOST LEVEL</span></summary>'
            echo '  <div class="body">'
            local nf
            for nf in ${nodefiles}; do
                local hn
                hn="$(basename "${nf}" | sed -e 's/^host__//' -e 's/\.node_memory\.csv$//')"
                local nodestatus
                nodestatus="$("${AWK_BIN}" -F',' '$1=="\"STATUS\""{gsub(/"/,"",$2); print $2}' "${nf}")"
                [ "${nodestatus}" = "CRITICAL" ] && total_node_warn=$(( total_node_warn + 1 ))
                [ "${nodestatus}" = "WARNING" ] && total_node_warn=$(( total_node_warn + 1 ))
                printf '<section class="subsection"><h3>Host: %s (%s)</h3>\n' "${hn}" "${nodestatus:-UNKNOWN}"
                echo '<table class="filter-table"><thead></thead><tbody>'
                "${AWK_BIN}" -F',' '$1 !~ /^"(SUMMARY|HOST_PHYSICAL_BYTES|TOTAL_CONFIGURED_BYTES|PCT_OF_PHYSICAL|STATUS)"/' "${nf}" > /dev/null
                csv_to_html_rows "${nf}"
                echo '</tbody></table></section>'
            done
            echo '  </div></details>'
        fi

        echo '</main>'

        printf '<footer>Generated by %s v%s &middot; retention %s days &middot; report path: %s</footer>\n' \
            "${SCRIPT_NAME}" "${SCRIPT_VERSION}" "${RETENTION_DAYS}" "${LATEST_DIR}"

        cat <<HTML_TAIL
<script>
  var STATS = { dbCount: ${db_count}, mismatches: ${total_mismatch}, memDrift: ${total_drift}, nodeWarn: ${total_node_warn} };
  function renderStats() {
    var strip = document.getElementById('summary-strip');
    if (!strip) return;
    var cards = [
      { label: 'Databases Audited', val: STATS.dbCount, cls: 'info' },
      { label: 'Parameter Mismatches', val: STATS.mismatches, cls: (STATS.mismatches > 0 ? 'bad' : 'ok') },
      { label: 'Memory Drift Findings', val: STATS.memDrift, cls: (STATS.memDrift > 0 ? 'warn' : 'ok') },
      { label: 'Node Memory Warnings', val: STATS.nodeWarn, cls: (STATS.nodeWarn > 0 ? 'bad' : 'ok') }
    ];
    var html = '';
    for (var i = 0; i < cards.length; i++) {
      html += '<div class="stat-card ' + cards[i].cls + '"><div class="num">' + cards[i].val + '</div><div class="label">' + cards[i].label + '</div></div>';
    }
    strip.innerHTML = html;
  }
  function expandAll() {
    document.querySelectorAll('details.island').forEach(function(d){ d.open = true; });
  }
  function collapseAll() {
    document.querySelectorAll('details.island').forEach(function(d){ d.open = false; });
  }
  function applyFilter() {
    var q = document.getElementById('filterBox').value.toLowerCase();
    document.querySelectorAll('details.island').forEach(function(island){
      var text = island.textContent.toLowerCase();
      var dbn = (island.getAttribute('data-dbname') || '').toLowerCase();
      if (q === '' || text.indexOf(q) !== -1 || dbn.indexOf(q) !== -1) {
        island.classList.remove('filter-hidden');
      } else {
        island.classList.add('filter-hidden');
      }
    });
  }
  renderStats();
</script>
</body>
</html>
HTML_TAIL
    } > "${html_file}"

    log INFO "HTML dashboard written to ${html_file} (${db_count} database island(s), ${total_mismatch} total mismatches, ${total_drift} memory drift findings)"

    # Export summary counters for the email step
    RPT_DB_COUNT="${db_count}"
    RPT_MISMATCH_COUNT="${total_mismatch}"
    RPT_DRIFT_COUNT="${total_drift}"
    RPT_NODE_WARN_COUNT="${total_node_warn}"
}

############################################
# ===== EMAIL (MIME multipart via sendmail, mailx fallback) ================
############################################
send_report_email() {
    local html_file="$1"
    if [ "${SEND_EMAIL}" != "1" ]; then
        log INFO "SEND_EMAIL=0, skipping email step (report available at ${html_file})"
        return 0
    fi
    if [ -z "${EMAIL_TO}" ]; then
        log WARN "EMAIL_TO is empty, skipping email step."
        return 0
    fi

    local subject
    subject="${EMAIL_SUBJECT_PREFIX} ${RPT_DB_COUNT:-0} DB(s), ${RPT_MISMATCH_COUNT:-0} mismatch(es), ${RPT_DRIFT_COUNT:-0} memory drift - $(date '+%Y-%m-%d %H:%M')"

    local boundary="dgaudit_$(date +%s)_$$"
    local msg_file
    msg_file="$(mk_tmp)"

    {
        printf 'From: %s\n' "${EMAIL_FROM}"
        printf 'To: %s\n' "${EMAIL_TO}"
        printf 'Subject: %s\n' "${subject}"
        printf 'MIME-Version: 1.0\n'
        printf 'Content-Type: multipart/mixed; boundary="%s"\n' "${boundary}"
        printf '\n'
        printf 'This is a MIME-formatted message. If you see this, your client does not support MIME.\n'
        printf '\n--%s\n' "${boundary}"
        printf 'Content-Type: text/html; charset=UTF-8\n'
        printf 'Content-Transfer-Encoding: 8bit\n\n'
        printf '<html><body style="font-family:Arial,sans-serif;">'
        printf '<h2>Oracle Data Guard Parameter Audit Summary</h2>'
        printf '<p>Host: <b>%s</b><br>Generated: %s</p>' "${HOST_NAME}" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf '<table cellpadding="8" style="border-collapse:collapse;">'
        printf '<tr style="background:#eef2ff;"><td><b>Databases audited</b></td><td>%s</td></tr>' "${RPT_DB_COUNT:-0}"
        printf '<tr style="background:%s;"><td><b>Parameter mismatches</b></td><td>%s</td></tr>' \
            "$( [ "${RPT_MISMATCH_COUNT:-0}" -gt 0 ] && echo '#fee2e2' || echo '#dcfce7' )" "${RPT_MISMATCH_COUNT:-0}"
        printf '<tr style="background:%s;"><td><b>Memory drift findings</b></td><td>%s</td></tr>' \
            "$( [ "${RPT_DRIFT_COUNT:-0}" -gt 0 ] && echo '#fef3c7' || echo '#dcfce7' )" "${RPT_DRIFT_COUNT:-0}"
        printf '<tr style="background:%s;"><td><b>Node memory warnings</b></td><td>%s</td></tr>' \
            "$( [ "${RPT_NODE_WARN_COUNT:-0}" -gt 0 ] && echo '#fee2e2' || echo '#dcfce7' )" "${RPT_NODE_WARN_COUNT:-0}"
        printf '</table>'
        printf '<p>The full interactive dashboard is attached (open it in a browser for expand/collapse and filtering). Raw CSVs are also attached for anything you want to pull into Excel/other tools.</p>'
        printf '<p style="color:#64748b;font-size:12px;">%s v%s &middot; report path: %s</p>' "${SCRIPT_NAME}" "${SCRIPT_VERSION}" "${LATEST_DIR}"
        printf '</body></html>\n'

        printf '\n--%s\n' "${boundary}"
        printf 'Content-Type: text/html; name="dashboard.html"\n'
        printf 'Content-Transfer-Encoding: base64\n'
        printf 'Content-Disposition: attachment; filename="dashboard_%s.html"\n\n' "${RUN_TS}"
        base64 "${html_file}" 2>/dev/null || openssl base64 -in "${html_file}" 2>/dev/null

        local f
        for f in "${THIS_RUN_ARCHIVE}"/*.csv; do
            [ -f "${f}" ] || continue
            printf '\n--%s\n' "${boundary}"
            printf 'Content-Type: text/csv; name="%s"\n' "$(basename "${f}")"
            printf 'Content-Transfer-Encoding: base64\n'
            printf 'Content-Disposition: attachment; filename="%s"\n\n' "$(basename "${f}")"
            base64 "${f}" 2>/dev/null || openssl base64 -in "${f}" 2>/dev/null
        done

        printf '\n--%s--\n' "${boundary}"
    } > "${msg_file}"

    if [ -n "${SENDMAIL_BIN}" ]; then
        if "${SENDMAIL_BIN}" -t < "${msg_file}"; then
            log INFO "Report email sent via sendmail to ${EMAIL_TO}"
            return 0
        else
            log WARN "sendmail invocation failed; will try mailx fallback."
        fi
    fi

    if command -v mailx >/dev/null 2>&1; then
        if command -v mailx >/dev/null 2>&1 && mailx -a "${html_file}" -s "${subject}" "${EMAIL_TO}" < /dev/null 2>/dev/null; then
            log WARN "Sent via mailx fallback (plain, attachment support varies by platform - HTML body not guaranteed)."
            return 0
        fi
    fi

    log WARN "Could not send email via sendmail or mailx. Report remains on disk at ${html_file}"
    return 1
}

############################################
# ===== HOUSEKEEPING =======================
############################################
housekeeping() {
    log INFO "Running housekeeping (retention: ${RETENTION_DAYS} days)..."

    find "${ARCHIVE_DIR}" -mindepth 1 -maxdepth 1 -type d -mtime "+${RETENTION_DAYS}" 2>/dev/null | while IFS= read -r d; do
        log INFO "Housekeeping: removing old archive directory ${d}"
        rm -rf "${d}" 2>/dev/null
    done

    find "${LOG_DIR}" -type f -name 'run_*.log' -mtime "+${RETENTION_DAYS}" -exec rm -f {} \; 2>/dev/null

    if [ -f "${MAIN_LOG}" ]; then
        local lines
        lines="$(wc -l < "${MAIN_LOG}" 2>/dev/null | tr -d ' ')"
        if [ -n "${lines}" ] && [ "${lines}" -gt "${MAIN_LOG_MAX_LINES}" ]; then
            local tmp_log
            tmp_log="$(mk_tmp)"
            tail -n "${MAIN_LOG_MAX_LINES}" "${MAIN_LOG}" > "${tmp_log}" && mv -f "${tmp_log}" "${MAIN_LOG}"
            log INFO "Housekeeping: trimmed ${MAIN_LOG} to last ${MAIN_LOG_MAX_LINES} lines (was ${lines})"
        fi
    fi

    find "${BASE_DIR}" -maxdepth 1 -name '.dgaudit_tmp.*' -mtime +1 -exec rm -f {} \; 2>/dev/null
    find "${BASE_DIR}" -maxdepth 1 -name '.write_test_*' -mtime +1 -exec rm -f {} \; 2>/dev/null

    if [ -n "${SQLDIR}" ] && [ "${SQLDIR}" != "${BASE_DIR}" ]; then
        rm -rf "${SQLDIR}" 2>/dev/null
    fi

    log INFO "Housekeeping complete."
}

############################################
# ===== MAIN ================================
############################################
main() {
    init_dirs
    log INFO "===== Starting ${SCRIPT_NAME} v${SCRIPT_VERSION} on ${HOST_NAME} (${OS_NAME}) at ${SCRIPT_START_EPOCH_HUMAN} ====="
    acquire_lock
    check_prereqs
    write_sql_scripts
    init_run_state

    local sids
    sids="$(discover_instances)"
    if [ -z "${sids}" ]; then
        log WARN "No eligible Oracle instances found running on this host (after exclusions). Nothing to audit this run."
    else
        log INFO "Discovered instance(s): $(printf '%s' "${sids}" | tr '\n' ' ')"
        local sid
        for sid in ${sids}; do
            process_instance "${sid}" || log WARN "SID ${sid}: processing ended with errors (see above); continuing with next instance."
        done
    fi

    compute_node_memory_summary

    local dbnames_for_compare
    dbnames_for_compare="$(for d in $(sort -u "${DBNAMES_SEEN_FILE}" 2>/dev/null); do sanitize "${d}"; done | sort -u)"
    local dbn
    for dbn in ${dbnames_for_compare}; do
        [ -z "${dbn}" ] && continue
        compare_db "${dbn}"
    done

    local html_file="${LATEST_DIR}/dashboard.html"
    generate_html_report "${html_file}"
    cp -f "${html_file}" "${THIS_RUN_ARCHIVE}/dashboard_${RUN_TS}.html" 2>/dev/null

    send_report_email "${html_file}"

    housekeeping

    log INFO "Run complete. Dashboard: ${html_file}"
}

main "$@"
