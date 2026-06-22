#!/bin/sh
# =============================================================================
# oracle_dg_param_check.sh
# Oracle Data Guard Parameter Comparison Script
# Compatible: Linux & Solaris
# Author: DBA Team
# Version: 2.0
# =============================================================================
# Usage:
#   ./oracle_dg_param_check.sh                   # Normal run (collect + compare)
#   ./oracle_dg_param_check.sh --report          # Generate HTML + send email
#   ./oracle_dg_param_check.sh --collect-only    # Only collect params to CSV
#   ./oracle_dg_param_check.sh --help            # Show help
# =============================================================================

# ---------------------------------------------------------------------------
# ========================  CONFIGURATION SECTION  ==========================
# ---------------------------------------------------------------------------

# Base directory for all script files (change this to your preferred location)
BASE_DIR="/u01/dg_param_check"

# CSV file to store collected parameters (shared across all DBs)
CSV_FILE="${BASE_DIR}/dg_params.csv"

# HTML report output file
HTML_REPORT="${BASE_DIR}/reports/dg_param_report.html"

# Log file
LOG_FILE="${BASE_DIR}/logs/dg_param_check_$(date '+%Y%m%d_%H%M%S').log"

# Email configuration
EMAIL_TO="dba-team@yourcompany.com"
EMAIL_FROM="oracle-alerts@yourcompany.com"
EMAIL_SUBJECT="Oracle DG Parameter Comparison Report - $(date '+%Y-%m-%d')"
SMTP_SERVER="mailrelay.yourcompany.com"        # Used by sendmail/mailx
# Set to "mailx" or "sendmail" or "mutt"
EMAIL_METHOD="mailx"

# ORA error code to write when parameter mismatch found
MISMATCH_ORA_CODE="20001"
MISMATCH_MESSAGE="DG Parameter mismatch detected between primary and standby"

# Parameters to EXCLUDE from comparison (comma-separated, no spaces)
# These are regex patterns matched against parameter name
EXCLUDE_PARAMS="audit_file_dest|background_dump_dest|core_dump_dest|user_dump_dest|db_recovery_file_dest|diagnostic_dest|local_listener|fal_server|fal_client|log_archive_dest_1|log_archive_dest_2|service_names|instance_name|db_unique_name"

# Processes to SKIP when scanning pmon (ASM, APX, MGMT instances)
SKIP_INSTANCES="^[+]|_MGMTDB|^APX|^MGMT|^-MGMT"

# DGmgrl binary name (usually dgmgrl)
DGMGRL_BIN="dgmgrl"

# How many days to keep old log files
LOG_RETENTION_DAYS=30

# ---------------------------------------------------------------------------
# ========================  END CONFIGURATION  ==============================
# ---------------------------------------------------------------------------

# Script internals - do not modify below unless you know what you are doing
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OS_TYPE=$(uname -s)
HOSTNAME=$(hostname)
RUN_DATE=$(date '+%Y-%m-%d %H:%M:%S')
RUN_EPOCH=$(date '+%s' 2>/dev/null || date '+%Y%m%d%H%M%S')
MODE="normal"

# CSV columns
CSV_HEADER="DB_UNIQUE_NAME,ROLE,HOST,COLLECTION_DATE,PARAMETER_NAME,PARAMETER_VALUE,DB_VERSION,DGBROKER_ENABLED,STANDBY_DETECTED,PRIMARY_DB_UNIQUE_NAME"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

log_info()  { log "INFO  : $*"; }
log_warn()  { log "WARN  : $*"; }
log_error() { log "ERROR : $*"; }
log_debug() { [ "${DEBUG:-0}" = "1" ] && log "DEBUG : $*"; }

separator() {
    log "----------------------------------------------------------------------"
}

print_usage() {
    cat <<EOF

${SCRIPT_NAME} - Oracle Data Guard Parameter Comparison Tool

USAGE:
  ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
  (none)            Normal run: collect parameters, compare if both sides present
  --collect-only    Only collect parameters into CSV, skip comparison
  --report          Generate HTML report and send email (no new collection)
  --report-only     Alias for --report
  --force-compare   Force comparison even if already compared today
  --help, -h        Show this help message

CONFIGURATION:
  Edit the CONFIGURATION SECTION at the top of this script to set:
  - BASE_DIR         : Working directory
  - CSV_FILE         : Shared CSV file path
  - EMAIL_*          : Email settings
  - EXCLUDE_PARAMS   : Parameters to skip in comparison

EXAMPLES:
  # Run on primary (collect)
  ${SCRIPT_NAME}

  # Run on standby (collect + auto-compare if primary data exists)
  ${SCRIPT_NAME}

  # Generate HTML report and email it
  ${SCRIPT_NAME} --report

  # Debug mode
  DEBUG=1 ${SCRIPT_NAME}

EOF
    exit 0
}

# Detect OS-compatible commands
setup_os_compat() {
    case "${OS_TYPE}" in
        SunOS|Solaris)
            AWK="nawk"
            # Solaris date does not support %s epoch; use perl if available
            if perl -e 'print time' >/dev/null 2>&1; then
                RUN_EPOCH=$(perl -e 'print time')
            else
                RUN_EPOCH=$(date '+%Y%m%d%H%M%S')
            fi
            PGREP_CMD="pgrep -lx"
            ;;
        Linux)
            AWK="awk"
            RUN_EPOCH=$(date '+%s')
            PGREP_CMD="pgrep -a"
            ;;
        *)
            AWK="awk"
            PGREP_CMD="pgrep -a"
            ;;
    esac
    log_info "OS detected: ${OS_TYPE}, AWK: ${AWK}"
}

# Create required directories
setup_dirs() {
    for dir in "${BASE_DIR}" "${BASE_DIR}/reports" "${BASE_DIR}/logs" "${BASE_DIR}/locks"; do
        if [ ! -d "${dir}" ]; then
            mkdir -p "${dir}" || { echo "ERROR: Cannot create directory ${dir}"; exit 1; }
        fi
    done
}

# =============================================================================
# ORACLE ENVIRONMENT DETECTION
# =============================================================================

# Find all running Oracle instances (excluding ASM/APX/MGMT)
get_running_instances() {
    log_info "Scanning for running Oracle PMON processes..."
    INSTANCES=""

    # Try ps-based detection (most compatible)
    # pmon process name format: ora_pmon_<SID>
    PMON_LIST=$(ps -ef 2>/dev/null | grep 'ora_pmon_' | grep -v grep | \
        ${AWK} '{
            for(i=1;i<=NF;i++) {
                if ($i ~ /ora_pmon_/) {
                    split($i,a,"ora_pmon_")
                    print a[2]
                }
            }
        }')

    if [ -z "${PMON_LIST}" ]; then
        # Try alternate format (some OS show it differently)
        PMON_LIST=$(ps -ef 2>/dev/null | grep '[o]ra_pmon' | \
            ${AWK} '{print $NF}' | sed 's/ora_pmon_//')
    fi

    for SID in ${PMON_LIST}; do
        # Skip blank
        [ -z "${SID}" ] && continue
        # Skip ASM (+ASM), APX, MGMT instances
        if echo "${SID}" | grep -qE "^[+]|_MGMTDB$|^APX|^MGMT"; then
            log_info "Skipping instance: ${SID} (ASM/APX/MGMT)"
            continue
        fi
        INSTANCES="${INSTANCES} ${SID}"
    done

    INSTANCES=$(echo "${INSTANCES}" | ${AWK} '{$1=$1};1')  # trim
    log_info "Running Oracle instances found: [${INSTANCES}]"
    echo "${INSTANCES}"
}

# Find ORACLE_HOME for a given SID
get_oracle_home() {
    local SID="$1"
    local OH=""

    # Method 1: /etc/oratab (Linux/Solaris standard)
    for ORATAB in /etc/oratab /var/opt/oracle/oratab; do
        if [ -f "${ORATAB}" ]; then
            OH=$(grep -v '^#' "${ORATAB}" | grep -v '^$' | \
                grep "^${SID}:" | head -1 | cut -d: -f2)
            if [ -n "${OH}" ] && [ -d "${OH}" ]; then
                log_debug "OH for ${SID} from oratab: ${OH}"
                echo "${OH}"
                return 0
            fi
            # Try case-insensitive
            OH=$(grep -v '^#' "${ORATAB}" | grep -v '^$' | \
                ${AWK} -F: -v sid="${SID}" 'tolower($1)==tolower(sid){print $2;exit}')
            if [ -n "${OH}" ] && [ -d "${OH}" ]; then
                log_debug "OH for ${SID} from oratab (case-insensitive): ${OH}"
                echo "${OH}"
                return 0
            fi
        fi
    done

    # Method 2: Find oracle binary in process command for this SID
    OH=$(ps -ef | grep "ora_pmon_${SID}" | grep -v grep | \
        ${AWK} '{print $8}' | sed 's|/bin/oracle||' | head -1)
    if [ -n "${OH}" ] && [ -d "${OH}" ]; then
        log_debug "OH for ${SID} from process: ${OH}"
        echo "${OH}"
        return 0
    fi

    # Method 3: Check common OH locations
    for BASE in /u01/app/oracle/product /opt/oracle/product /oracle/product; do
        if [ -d "${BASE}" ]; then
            for VER_DIR in $(ls -d ${BASE}/*/ 2>/dev/null | sort -rV | head -5); do
                for TYPE in db_1 dbhome_1 db db_home; do
                    CANDIDATE="${VER_DIR}${TYPE}"
                    if [ -d "${CANDIDATE}" ] && [ -f "${CANDIDATE}/bin/sqlplus" ]; then
                        log_warn "OH for ${SID} guessed from path: ${CANDIDATE}"
                        echo "${CANDIDATE}"
                        return 0
                    fi
                done
                if [ -f "${VER_DIR}bin/sqlplus" ]; then
                    echo "${VER_DIR%/}"
                    return 0
                fi
            done
        fi
    done

    log_error "Cannot determine ORACLE_HOME for SID: ${SID}"
    return 1
}

# =============================================================================
# DATA GUARD DETECTION
# =============================================================================

# Check if DG broker is enabled and if a standby exists
check_dg_enabled() {
    local SID="$1"
    local OH="$2"

    export ORACLE_SID="${SID}"
    export ORACLE_HOME="${OH}"
    export PATH="${OH}/bin:${PATH}"
    export LD_LIBRARY_PATH="${OH}/lib:${LD_LIBRARY_PATH}"

    # Check 1: dg_broker_start parameter
    DGB_START=$(sqlplus -S / as sysdba <<SQLEOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF VERIFY OFF TRIMSPOOL ON
SELECT LOWER(value) FROM v\$parameter WHERE name='dg_broker_start';
EXIT;
SQLEOF
)
    DGB_START=$(echo "${DGB_START}" | tr -d ' \n\r')
    log_debug "dg_broker_start for ${SID}: [${DGB_START}]"

    if [ "${DGB_START}" != "true" ]; then
        log_info "${SID}: dg_broker_start=FALSE, skipping DG check"
        echo "NODG"
        return 0
    fi

    # Check 2: dgmgrl show configuration
    if command -v ${DGMGRL_BIN} >/dev/null 2>&1; then
        DG_CONFIG=$(echo "show configuration;" | ${DGMGRL_BIN} -silent / 2>/dev/null)
        if echo "${DG_CONFIG}" | grep -qiE "ORA-|Error|Cannot connect|not found"; then
            log_warn "${SID}: dgmgrl failed or no configuration"
            echo "NODG"
            return 0
        fi
        if echo "${DG_CONFIG}" | grep -qiE "Primary|Physical Standby|Logical Standby|Snapshot Standby"; then
            log_info "${SID}: DG configuration found via dgmgrl"
            echo "DG_ENABLED"
            return 0
        fi
    fi

    # DG broker enabled but dgmgrl not conclusive
    echo "DG_BROKER_ONLY"
}

# Get database role (PRIMARY/STANDBY)
get_db_role() {
    local SID="$1"
    local OH="$2"

    export ORACLE_SID="${SID}"
    export ORACLE_HOME="${OH}"
    export PATH="${OH}/bin:${PATH}"
    export LD_LIBRARY_PATH="${OH}/lib:${LD_LIBRARY_PATH}"

    ROLE=$(sqlplus -S / as sysdba <<SQLEOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF VERIFY OFF TRIMSPOOL ON
SELECT database_role FROM v\$database;
EXIT;
SQLEOF
)
    ROLE=$(echo "${ROLE}" | tr -d ' \n\r' | tr '[:lower:]' '[:upper:]')
    log_debug "Role for ${SID}: [${ROLE}]"
    echo "${ROLE}"
}

# Get DB unique name and primary db unique name
get_db_names() {
    local SID="$1"
    local OH="$2"

    export ORACLE_SID="${SID}"
    export ORACLE_HOME="${OH}"
    export PATH="${OH}/bin:${PATH}"
    export LD_LIBRARY_PATH="${OH}/lib:${LD_LIBRARY_PATH}"

    DB_NAMES=$(sqlplus -S / as sysdba <<SQLEOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF VERIFY OFF TRIMSPOOL ON LINESIZE 200
SELECT d.db_unique_name||'|'||d.db_version||'|'||NVL(
    (SELECT value FROM v\$dataguard_config WHERE dest_id=1 AND dest_role='PRIMARY DATABASE'),
    'UNKNOWN'
)
FROM v\$database d;
EXIT;
SQLEOF
)
    echo "${DB_NAMES}" | tr -d ' \r' | grep '|' | head -1
}

# Get primary db_unique_name via dgmgrl
get_primary_via_dgmgrl() {
    local SID="$1"
    local OH="$2"

    export ORACLE_SID="${SID}"
    export ORACLE_HOME="${OH}"
    export PATH="${OH}/bin:${PATH}"

    PRIMARY_NAME=$(echo "show configuration;" | ${DGMGRL_BIN} -silent / 2>/dev/null | \
        grep -i "Primary database" | ${AWK} '{print $1}' | tr -d '"' | head -1)

    if [ -z "${PRIMARY_NAME}" ]; then
        # Try parsing differently
        PRIMARY_NAME=$(echo "show configuration verbose;" | ${DGMGRL_BIN} -silent / 2>/dev/null | \
            ${AWK} '/Primary database/{getline; print $1}' | tr -d '"' | head -1)
    fi
    echo "${PRIMARY_NAME}"
}

# =============================================================================
# PARAMETER COLLECTION
# =============================================================================

collect_parameters() {
    local SID="$1"
    local OH="$2"
    local ROLE="$3"
    local DB_UNIQUE_NAME="$4"
    local DB_VERSION="$5"
    local PRIMARY_DB_UNIQUE_NAME="$6"
    local DG_STATUS="$7"

    export ORACLE_SID="${SID}"
    export ORACLE_HOME="${OH}"
    export PATH="${OH}/bin:${PATH}"
    export LD_LIBRARY_PATH="${OH}/lib:${LD_LIBRARY_PATH}"

    log_info "Collecting parameters for ${DB_UNIQUE_NAME} (${ROLE})..."

    # Collect all non-hidden, non-deprecated parameters
    PARAMS=$(sqlplus -S / as sysdba <<SQLEOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF VERIFY OFF TRIMSPOOL ON LINESIZE 500
SET COLSEP '|'
SELECT name||'|'||value
FROM v\$parameter
WHERE name NOT LIKE '\_%' ESCAPE '\'
AND isdefault != 'TRUE'
ORDER BY name;
EXIT;
SQLEOF
)

    if [ -z "${PARAMS}" ]; then
        log_error "No parameters returned for ${SID}. Check connectivity."
        return 1
    fi

    local COLLECTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')
    local PARAM_COUNT=0
    local LOCK_FILE="${BASE_DIR}/locks/csv.lock"

    # Build exclude pattern from config
    EXCLUDE_PATTERN="${EXCLUDE_PARAMS}"

    # Write to CSV with lock to prevent concurrent writes
    # Use lock file approach compatible with Linux and Solaris
    local MAX_WAIT=30
    local WAITED=0
    while [ -f "${LOCK_FILE}" ] && [ ${WAITED} -lt ${MAX_WAIT} ]; do
        sleep 1
        WAITED=$((WAITED+1))
    done
    if [ -f "${LOCK_FILE}" ]; then
        log_warn "Lock file exists after ${MAX_WAIT}s, proceeding anyway"
        rm -f "${LOCK_FILE}"
    fi
    touch "${LOCK_FILE}"

    # Initialize CSV if it doesn't exist
    if [ ! -f "${CSV_FILE}" ]; then
        echo "${CSV_HEADER}" > "${CSV_FILE}"
        log_info "Created new CSV file: ${CSV_FILE}"
    fi

    # Remove existing entries for this db_unique_name (dedup)
    TMP_CSV="${CSV_FILE}.tmp.$$"
    head -1 "${CSV_FILE}" > "${TMP_CSV}"
    # Keep all rows except those matching this db_unique_name
    tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v db="${DB_UNIQUE_NAME}" \
        '$1 != db {print}' >> "${TMP_CSV}"
    mv "${TMP_CSV}" "${CSV_FILE}"
    log_info "Removed existing entries for ${DB_UNIQUE_NAME} from CSV"

    # Write new parameter entries
    echo "${PARAMS}" | while IFS='|' read PNAME PVALUE; do
        PNAME=$(echo "${PNAME}" | tr -d ' \r')
        PVALUE=$(echo "${PVALUE}" | tr -d '\r')
        [ -z "${PNAME}" ] && continue

        # Skip excluded parameters
        if echo "${PNAME}" | grep -qE "${EXCLUDE_PATTERN}"; then
            continue
        fi

        # Escape commas/quotes in value for CSV safety
        PVALUE_ESC=$(echo "${PVALUE}" | sed 's/"/""/g')
        # Wrap in quotes if contains comma
        if echo "${PVALUE_ESC}" | grep -q ','; then
            PVALUE_ESC="\"${PVALUE_ESC}\""
        fi

        echo "${DB_UNIQUE_NAME},${ROLE},${HOSTNAME},${COLLECTION_DATE},${PNAME},${PVALUE_ESC},${DB_VERSION},${DG_STATUS},YES,${PRIMARY_DB_UNIQUE_NAME}" >> "${CSV_FILE}"
        PARAM_COUNT=$((PARAM_COUNT+1))
    done

    rm -f "${LOCK_FILE}"
    log_info "Collected ${PARAM_COUNT} parameters for ${DB_UNIQUE_NAME}"
    return 0
}

# =============================================================================
# PARAMETER COMPARISON
# =============================================================================

# Check if we have both primary and standby data for a given primary
should_compare() {
    local PRIMARY_DB="$1"

    # Find all unique db_unique_names where primary_db_unique_name = PRIMARY_DB
    STANDBYS=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' \
        -v pdb="${PRIMARY_DB}" \
        '$10 == pdb && $2 ~ /STANDBY/ {print $1}' | sort -u)

    # Also check if PRIMARY itself is in CSV
    HAS_PRIMARY=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' \
        -v pdb="${PRIMARY_DB}" \
        '$1 == pdb && $2 == "PRIMARY" {print "YES"; exit}')

    if [ -n "${HAS_PRIMARY}" ] && [ -n "${STANDBYS}" ]; then
        echo "YES"
    else
        echo "NO"
    fi
}

# Core comparison function
compare_parameters() {
    local PRIMARY_DB="$1"
    log_info "Comparing parameters for primary: ${PRIMARY_DB}"

    # Get standbys associated with this primary
    STANDBYS=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' \
        -v pdb="${PRIMARY_DB}" \
        '$10 == pdb && $2 ~ /STANDBY/ {print $1}' | sort -u)

    if [ -z "${STANDBYS}" ]; then
        log_warn "No standby data found for primary: ${PRIMARY_DB}"
        return 1
    fi

    REPORT_FILE="${BASE_DIR}/reports/compare_${PRIMARY_DB}_$(date '+%Y%m%d_%H%M%S').txt"
    MISMATCH_COUNT=0
    MATCH_COUNT=0

    log_info "Standbys found: ${STANDBYS}"

    for STANDBY_DB in ${STANDBYS}; do
        log_info "  Comparing ${PRIMARY_DB} vs ${STANDBY_DB}"

        # Extract primary parameters into temp file
        TMP_PRI="${BASE_DIR}/locks/pri_${PRIMARY_DB}.$$"
        TMP_STB="${BASE_DIR}/locks/stb_${STANDBY_DB}.$$"
        TMP_DIFF="${BASE_DIR}/locks/diff_${PRIMARY_DB}_${STANDBY_DB}.$$"

        tail -n +2 "${CSV_FILE}" | ${AWK} -F',' \
            -v db="${PRIMARY_DB}" \
            '$1 == db {print $5","$6}' | sort > "${TMP_PRI}"

        tail -n +2 "${CSV_FILE}" | ${AWK} -F',' \
            -v db="${STANDBY_DB}" \
            '$1 == db {print $5","$6}' | sort > "${TMP_STB}"

        # Find parameters only in primary
        ONLY_PRI=$(comm -23 \
            <(${AWK} -F',' '{print $1}' "${TMP_PRI}" | sort) \
            <(${AWK} -F',' '{print $1}' "${TMP_STB}" | sort))

        # Find parameters only in standby
        ONLY_STB=$(comm -13 \
            <(${AWK} -F',' '{print $1}' "${TMP_PRI}" | sort) \
            <(${AWK} -F',' '{print $1}' "${TMP_STB}" | sort))

        # Find parameters in both but with different values
        echo "DB_UNIQUE_NAME_PRI,DB_UNIQUE_NAME_STB,PARAMETER,PRIMARY_VALUE,STANDBY_VALUE,STATUS" > "${TMP_DIFF}"

        # Compare common parameters
        ${AWK} -F',' 'NR==FNR{a[$1]=$2;next} ($1 in a) && a[$1]!=$2 {print $1"|"a[$1]"|"$2}' \
            "${TMP_PRI}" "${TMP_STB}" | while IFS='|' read PNAME PVAL_PRI PVAL_STB; do
            echo "${PRIMARY_DB},${STANDBY_DB},${PNAME},${PVAL_PRI},${PVAL_STB},MISMATCH" >> "${TMP_DIFF}"
            MISMATCH_COUNT=$((MISMATCH_COUNT+1))
        done

        # Add params only in primary
        for P in ${ONLY_PRI}; do
            PVAL=$(grep "^${P}," "${TMP_PRI}" | cut -d',' -f2)
            echo "${PRIMARY_DB},${STANDBY_DB},${P},${PVAL},NOT_SET,MISMATCH_MISSING_STB" >> "${TMP_DIFF}"
            MISMATCH_COUNT=$((MISMATCH_COUNT+1))
        done

        # Add params only in standby
        for P in ${ONLY_STB}; do
            PVAL=$(grep "^${P}," "${TMP_STB}" | cut -d',' -f2)
            echo "${PRIMARY_DB},${STANDBY_DB},NOT_SET,${PVAL},MISMATCH_MISSING_PRI" >> "${TMP_DIFF}"
            MISMATCH_COUNT=$((MISMATCH_COUNT+1))
        done

        # Store diff results
        DIFF_OUT="${BASE_DIR}/reports/diff_${PRIMARY_DB}_vs_${STANDBY_DB}.csv"
        cp "${TMP_DIFF}" "${DIFF_OUT}"

        log_info "  Diff written to: ${DIFF_OUT}"
        log_info "  Mismatches for ${STANDBY_DB}: $(tail -n +2 ${TMP_DIFF} | wc -l)"

        rm -f "${TMP_PRI}" "${TMP_STB}" "${TMP_DIFF}"
    done

    return 0
}

# Write ORA error to database when mismatches found
write_ora_error() {
    local SID="$1"
    local OH="$2"
    local STANDBY_DB="$3"
    local MISMATCH_DETAIL="$4"

    export ORACLE_SID="${SID}"
    export ORACLE_HOME="${OH}"
    export PATH="${OH}/bin:${PATH}"
    export LD_LIBRARY_PATH="${OH}/lib:${LD_LIBRARY_PATH}"

    log_info "Writing ORA-${MISMATCH_ORA_CODE} to database ${SID} alert log..."

    sqlplus -S / as sysdba <<SQLEOF 2>/dev/null
SET FEEDBACK OFF
BEGIN
    -- Log to alert log via DBMS_SYSTEM
    SYS.DBMS_SYSTEM.KSDWRT(2,
        'ORA-${MISMATCH_ORA_CODE}: ${MISMATCH_MESSAGE} with ${STANDBY_DB}. Details: ${MISMATCH_DETAIL}');

    -- Also try to write to a custom audit table if it exists
    EXECUTE IMMEDIATE
        'BEGIN
           INSERT INTO dba_dg_param_alerts
             (alert_date, primary_db, standby_db, ora_code, message, host)
           VALUES
             (SYSDATE, SYS_CONTEXT(''USERENV'',''DB_UNIQUE_NAME''),
              ''${STANDBY_DB}'', ${MISMATCH_ORA_CODE},
              ''${MISMATCH_MESSAGE}'', ''${HOSTNAME}'');
           COMMIT;
         END;'
    ;
EXCEPTION
    WHEN OTHERS THEN
        -- Table may not exist, that is ok - alert log entry is sufficient
        SYS.DBMS_SYSTEM.KSDWRT(2, 'DG_PARAM_CHECK: Custom audit table not found, alert log only');
END;
/
EXIT;
SQLEOF

    log_info "ORA error written to ${SID} alert log"
}

# Create the optional audit table (run once)
create_audit_table() {
    local SID="$1"
    local OH="$2"

    export ORACLE_SID="${SID}"
    export ORACLE_HOME="${OH}"
    export PATH="${OH}/bin:${PATH}"

    sqlplus -S / as sysdba <<SQLEOF 2>/dev/null
SET FEEDBACK OFF
BEGIN
    EXECUTE IMMEDIATE '
        CREATE TABLE dba_dg_param_alerts (
            alert_id     NUMBER GENERATED ALWAYS AS IDENTITY,
            alert_date   DATE DEFAULT SYSDATE,
            primary_db   VARCHAR2(128),
            standby_db   VARCHAR2(128),
            ora_code     NUMBER,
            message      VARCHAR2(4000),
            host         VARCHAR2(256),
            CONSTRAINT pk_dg_alerts PRIMARY KEY (alert_id)
        )';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -955 THEN NULL; -- Table already exists
        ELSE RAISE;
        END IF;
END;
/
EXIT;
SQLEOF
    log_info "Audit table ensured in ${SID}"
}

# =============================================================================
# HTML REPORT GENERATION
# =============================================================================

generate_html_report() {
    log_info "Generating HTML report..."

    mkdir -p "$(dirname ${HTML_REPORT})"

    # Gather all primary databases from CSV
    ALL_PRIMARIES=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' '$2=="PRIMARY"{print $1}' | sort -u)
    ALL_STANDBYS=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' '$2~/STANDBY/{print $1}' | sort -u)
    TOTAL_DBS=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' '{print $1}' | sort -u | wc -l | tr -d ' ')
    REPORT_TS=$(date '+%Y-%m-%d %H:%M:%S')

    # Count total mismatches across all diff files
    TOTAL_MISMATCHES=0
    DIFF_FILES=$(ls "${BASE_DIR}/reports/diff_"*.csv 2>/dev/null)
    for DF in ${DIFF_FILES}; do
        CNT=$(tail -n +2 "${DF}" 2>/dev/null | wc -l | tr -d ' ')
        TOTAL_MISMATCHES=$((TOTAL_MISMATCHES+CNT))
    done

    cat > "${HTML_REPORT}" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oracle DG Parameter Comparison Report</title>
<style>
  :root {
    --primary: #1a3a5c;
    --secondary: #2e6da4;
    --accent: #e8a020;
    --danger: #c0392b;
    --success: #27ae60;
    --warn: #f39c12;
    --bg: #f0f4f8;
    --card: #ffffff;
    --text: #2c3e50;
    --muted: #7f8c8d;
    --border: #dde3ec;
    --radius: 8px;
    --shadow: 0 2px 12px rgba(0,0,0,0.09);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: var(--bg);
         color: var(--text); font-size: 14px; }

  /* ---- HEADER ---- */
  .header {
    background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
    color: white; padding: 28px 40px;
    display: flex; align-items: center; justify-content: space-between;
    box-shadow: 0 3px 10px rgba(0,0,0,0.2);
  }
  .header h1 { font-size: 22px; font-weight: 700; letter-spacing: 0.5px; }
  .header .meta { font-size: 12px; opacity: 0.85; margin-top: 4px; }
  .oracle-badge {
    background: var(--accent); color: #fff; padding: 6px 14px;
    border-radius: 20px; font-size: 12px; font-weight: 700;
  }

  /* ---- NAVIGATION ---- */
  .nav { background: var(--primary); padding: 0 40px; display: flex; gap: 4px; }
  .nav a {
    color: rgba(255,255,255,0.75); text-decoration: none;
    padding: 12px 18px; display: inline-block; font-size: 13px;
    font-weight: 500; border-bottom: 3px solid transparent;
    transition: all 0.2s;
  }
  .nav a:hover, .nav a.active {
    color: white; border-bottom-color: var(--accent);
    background: rgba(255,255,255,0.08);
  }

  /* ---- LAYOUT ---- */
  .container { max-width: 1400px; margin: 0 auto; padding: 28px 40px; }

  /* ---- STAT CARDS ---- */
  .stats-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px; margin-bottom: 28px;
  }
  .stat-card {
    background: var(--card); border-radius: var(--radius);
    padding: 20px 22px; box-shadow: var(--shadow);
    border-left: 4px solid var(--secondary);
  }
  .stat-card.danger { border-left-color: var(--danger); }
  .stat-card.success { border-left-color: var(--success); }
  .stat-card.warn { border-left-color: var(--warn); }
  .stat-number { font-size: 32px; font-weight: 800; line-height: 1; margin-bottom: 4px; }
  .stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase;
                letter-spacing: 0.5px; }

  /* ---- TABS ---- */
  .tabs-wrapper { background: var(--card); border-radius: var(--radius);
                  box-shadow: var(--shadow); overflow: hidden; margin-bottom: 24px; }
  .tab-bar {
    display: flex; background: #f8fafc; border-bottom: 2px solid var(--border);
    overflow-x: auto; scrollbar-width: thin;
  }
  .tab-btn {
    padding: 12px 20px; border: none; background: none; cursor: pointer;
    font-size: 13px; font-weight: 600; color: var(--muted); white-space: nowrap;
    border-bottom: 3px solid transparent; margin-bottom: -2px;
    transition: all 0.2s; flex-shrink: 0;
  }
  .tab-btn:hover { color: var(--secondary); background: rgba(46,109,164,0.05); }
  .tab-btn.active { color: var(--secondary); border-bottom-color: var(--secondary);
                    background: white; }
  .tab-btn.has-issues { color: var(--danger); }
  .tab-btn.has-issues.active { border-bottom-color: var(--danger); }
  .tab-content { display: none; padding: 24px; }
  .tab-content.active { display: block; }

  /* ---- TABLES ---- */
  .table-wrap { overflow-x: auto; border-radius: 6px; border: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th {
    background: var(--primary); color: white; padding: 10px 14px;
    text-align: left; font-weight: 600; font-size: 12px;
    text-transform: uppercase; letter-spacing: 0.4px; white-space: nowrap;
  }
  tbody tr { border-bottom: 1px solid var(--border); transition: background 0.15s; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #f5f8fc; }
  td { padding: 9px 14px; vertical-align: top; }
  td:first-child { font-weight: 600; color: var(--primary); }

  /* ---- BADGES ---- */
  .badge {
    display: inline-block; padding: 3px 10px; border-radius: 20px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.3px;
  }
  .badge-primary { background: #dbeafe; color: #1d4ed8; }
  .badge-standby { background: #d1fae5; color: #065f46; }
  .badge-mismatch { background: #fee2e2; color: #991b1b; }
  .badge-match { background: #d1fae5; color: #065f46; }
  .badge-warn { background: #fef3c7; color: #92400e; }

  /* ---- DIFF HIGHLIGHTS ---- */
  .val-pri { background: #fff3cd; padding: 2px 6px; border-radius: 4px;
             font-family: monospace; font-size: 12px; word-break: break-all; }
  .val-stb { background: #cce5ff; padding: 2px 6px; border-radius: 4px;
             font-family: monospace; font-size: 12px; word-break: break-all; }
  .val-match { color: var(--success); font-family: monospace; font-size: 12px; }

  /* ---- ALERTS ---- */
  .alert { border-radius: 6px; padding: 14px 18px; margin-bottom: 16px;
           display: flex; align-items: flex-start; gap: 10px; }
  .alert-success { background: #d1fae5; border: 1px solid #6ee7b7; }
  .alert-danger  { background: #fee2e2; border: 1px solid #fca5a5; }
  .alert-warn    { background: #fef3c7; border: 1px solid #fcd34d; }
  .alert-icon { font-size: 18px; flex-shrink: 0; }

  /* ---- SEARCH ---- */
  .search-bar {
    padding: 8px 14px; border: 1px solid var(--border); border-radius: 6px;
    font-size: 13px; width: 280px; margin-bottom: 14px; outline: none;
    transition: border 0.2s;
  }
  .search-bar:focus { border-color: var(--secondary); }

  /* ---- FOOTER ---- */
  .footer {
    text-align: center; padding: 20px; color: var(--muted); font-size: 12px;
    border-top: 1px solid var(--border); margin-top: 40px;
  }

  /* ---- INDEX PAGE ---- */
  .db-index-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px;
  }
  .db-card {
    background: var(--card); border-radius: var(--radius); padding: 20px;
    box-shadow: var(--shadow); border-top: 4px solid var(--secondary);
    transition: transform 0.15s, box-shadow 0.15s; cursor: pointer;
  }
  .db-card:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,0.12); }
  .db-card.has-issues { border-top-color: var(--danger); }
  .db-card.ok { border-top-color: var(--success); }
  .db-card h3 { font-size: 15px; margin-bottom: 8px; }
  .db-card .db-meta { font-size: 12px; color: var(--muted); line-height: 1.7; }
  .db-card .status-row { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }

  @media (max-width: 768px) {
    .header { padding: 18px 20px; }
    .nav { padding: 0 20px; }
    .container { padding: 18px 20px; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
HTMLEOF

    # Inject dynamic values
    cat >> "${HTML_REPORT}" <<HTMLEOF2

<div class="header">
  <div>
    <h1>&#128202; Oracle Data Guard — Parameter Comparison Report</h1>
    <div class="meta">Generated: ${REPORT_TS} &nbsp;|&nbsp; Host: ${HOSTNAME} &nbsp;|&nbsp; Total Databases: ${TOTAL_DBS}</div>
  </div>
  <div class="oracle-badge">Oracle DG Monitor</div>
</div>

<nav class="nav">
  <a href="#" class="active" onclick="showPage('landing')">&#127968; Home</a>
  <a href="#" onclick="showPage('index')">&#128196; Database Index</a>
  <a href="#" onclick="showPage('comparison')">&#128269; Comparison</a>
  <a href="#" onclick="showPage('csv-data')">&#128202; Raw Data</a>
</nav>

<div class="container">

<!-- ===================== STATS ===================== -->
<div class="stats-grid">
  <div class="stat-card success">
    <div class="stat-number">${TOTAL_DBS}</div>
    <div class="stat-label">Databases Monitored</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">$(echo "${ALL_PRIMARIES}" | wc -w | tr -d ' ')</div>
    <div class="stat-label">Primary Databases</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">$(echo "${ALL_STANDBYS}" | wc -w | tr -d ' ')</div>
    <div class="stat-label">Standby Databases</div>
  </div>
  <div class="stat-card $([ ${TOTAL_MISMATCHES} -gt 0 ] && echo danger || echo success)">
    <div class="stat-number">${TOTAL_MISMATCHES}</div>
    <div class="stat-label">Total Mismatches</div>
  </div>
</div>

<!-- ===================== LANDING PAGE ===================== -->
<div id="page-landing" class="page-section">
  <div class="tabs-wrapper">
    <div style="padding:24px;">
      <h2 style="margin-bottom:16px; color:var(--primary);">&#127968; Welcome to Oracle DG Parameter Monitor</h2>
HTMLEOF2

    if [ ${TOTAL_MISMATCHES} -gt 0 ]; then
        cat >> "${HTML_REPORT}" <<HTMLEOF3
      <div class="alert alert-danger">
        <span class="alert-icon">&#9888;</span>
        <div><strong>Attention Required:</strong> ${TOTAL_MISMATCHES} parameter mismatch(es) found between primary and standby databases. Review the Comparison tab for details.</div>
      </div>
HTMLEOF3
    else
        cat >> "${HTML_REPORT}" <<HTMLEOF3
      <div class="alert alert-success">
        <span class="alert-icon">&#10004;</span>
        <div><strong>All Clear:</strong> No parameter mismatches detected between primary and standby databases.</div>
      </div>
HTMLEOF3
    fi

    cat >> "${HTML_REPORT}" <<HTMLEOF4
      <p style="color:var(--muted); line-height:1.8; margin-bottom:16px;">
        This report shows Oracle Data Guard parameter comparisons between primary and standby databases.
        Use the tabs above to navigate between databases, comparison results, and raw data.
      </p>
      <table style="width:auto; min-width:400px;">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Report Generated</td><td>${REPORT_TS}</td></tr>
          <tr><td>Primary Databases</td><td>$(echo "${ALL_PRIMARIES}" | tr ' ' '\n' | grep -v '^$' | wc -l | tr -d ' ')</td></tr>
          <tr><td>Standby Databases</td><td>$(echo "${ALL_STANDBYS}" | tr ' ' '\n' | grep -v '^$' | wc -l | tr -d ' ')</td></tr>
          <tr><td>Total Mismatches</td><td><span class="badge $([ ${TOTAL_MISMATCHES} -gt 0 ] && echo badge-mismatch || echo badge-match)">${TOTAL_MISMATCHES}</span></td></tr>
          <tr><td>Report Host</td><td>${HOSTNAME}</td></tr>
          <tr><td>CSV Data File</td><td><code>${CSV_FILE}</code></td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- ===================== DATABASE INDEX ===================== -->
<div id="page-index" class="page-section" style="display:none;">
  <div class="tabs-wrapper">
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab(this,'idx-all')">All Databases</button>
      <button class="tab-btn" onclick="switchTab(this,'idx-primary')">Primary</button>
      <button class="tab-btn" onclick="switchTab(this,'idx-standby')">Standby</button>
    </div>
    <div id="idx-all" class="tab-content active">
      <div class="db-index-grid">
HTMLEOF4

    # Generate DB cards
    ALL_DBS=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' '{print $1}' | sort -u)
    for DB in ${ALL_DBS}; do
        ROLE=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $2;exit}')
        DB_VER=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $7;exit}')
        DB_HOST=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $3;exit}')
        COLL_DT=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $4;exit}')
        PARAM_CNT=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d' | wc -l | tr -d ' ')

        # Check mismatches for this DB
        DB_MISMATCHES=0
        for DF in $(ls "${BASE_DIR}/reports/diff_${DB}_vs_"*.csv 2>/dev/null) \
                   $(ls "${BASE_DIR}/reports/diff_"*"_vs_${DB}.csv" 2>/dev/null); do
            CNT=$(tail -n +2 "${DF}" 2>/dev/null | wc -l | tr -d ' ')
            DB_MISMATCHES=$((DB_MISMATCHES+CNT))
        done

        CARD_CLASS="ok"
        [ ${DB_MISMATCHES} -gt 0 ] && CARD_CLASS="has-issues"
        [ "${ROLE}" = "PRIMARY" ] && ROLE_BADGE="badge-primary" || ROLE_BADGE="badge-standby"

        cat >> "${HTML_REPORT}" <<DBCARDEOF
        <div class="db-card ${CARD_CLASS}" onclick="showPage('comparison')">
          <h3>${DB}</h3>
          <div class="db-meta">
            &#128187; Host: ${DB_HOST}<br>
            &#128338; Collected: ${COLL_DT}<br>
            &#128200; Version: ${DB_VER}<br>
            &#128202; Parameters: ${PARAM_CNT}
          </div>
          <div class="status-row">
            <span class="badge ${ROLE_BADGE}">${ROLE}</span>
            $([ ${DB_MISMATCHES} -gt 0 ] && echo "<span class='badge badge-mismatch'>&#9888; ${DB_MISMATCHES} Mismatch(es)</span>" || echo "<span class='badge badge-match'>&#10004; OK</span>")
          </div>
        </div>
DBCARDEOF
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF5
      </div>
    </div>
    <div id="idx-primary" class="tab-content">
      <div class="db-index-grid">
HTMLEOF5

    # Primary cards
    for DB in ${ALL_PRIMARIES}; do
        DB_VER=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $7;exit}')
        DB_HOST=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $3;exit}')
        PARAM_CNT=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d' | wc -l | tr -d ' ')
        DB_MISMATCHES=0
        for DF in $(ls "${BASE_DIR}/reports/diff_${DB}_vs_"*.csv 2>/dev/null); do
            CNT=$(tail -n +2 "${DF}" 2>/dev/null | wc -l | tr -d ' ')
            DB_MISMATCHES=$((DB_MISMATCHES+CNT))
        done
        CARD_CLASS="ok"; [ ${DB_MISMATCHES} -gt 0 ] && CARD_CLASS="has-issues"
        cat >> "${HTML_REPORT}" <<DBPRIEOF
        <div class="db-card ${CARD_CLASS}">
          <h3>${DB}</h3>
          <div class="db-meta">&#128187; ${DB_HOST}<br>&#128200; ${DB_VER}<br>&#128202; ${PARAM_CNT} params</div>
          <div class="status-row">
            <span class="badge badge-primary">PRIMARY</span>
            $([ ${DB_MISMATCHES} -gt 0 ] && echo "<span class='badge badge-mismatch'>&#9888; ${DB_MISMATCHES}</span>" || echo "<span class='badge badge-match'>&#10004; OK</span>")
          </div>
        </div>
DBPRIEOF
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF6
      </div>
    </div>
    <div id="idx-standby" class="tab-content">
      <div class="db-index-grid">
HTMLEOF6

    for DB in ${ALL_STANDBYS}; do
        DB_VER=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $7;exit}')
        DB_HOST=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $3;exit}')
        PARAM_CNT=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d' | wc -l | tr -d ' ')
        cat >> "${HTML_REPORT}" <<DBSTBEOF
        <div class="db-card ok">
          <h3>${DB}</h3>
          <div class="db-meta">&#128187; ${DB_HOST}<br>&#128200; ${DB_VER}<br>&#128202; ${PARAM_CNT} params</div>
          <div class="status-row"><span class="badge badge-standby">STANDBY</span></div>
        </div>
DBSTBEOF
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF7
      </div>
    </div>
  </div>
</div>

<!-- ===================== COMPARISON ===================== -->
<div id="page-comparison" class="page-section" style="display:none;">
  <div class="tabs-wrapper">
    <div class="tab-bar" id="cmp-tab-bar">
      <button class="tab-btn active" onclick="switchTab(this,'cmp-overview')">Overview</button>
HTMLEOF7

    # One tab per primary→standby pair
    for DF in $(ls "${BASE_DIR}/reports/diff_"*.csv 2>/dev/null | sort); do
        BASENAME=$(basename "${DF}" .csv)
        PAIR=$(echo "${BASENAME}" | sed 's/^diff_//')
        MCOUNT=$(tail -n +2 "${DF}" | wc -l | tr -d ' ')
        ISSUE_CLASS=""
        [ ${MCOUNT} -gt 0 ] && ISSUE_CLASS=" has-issues"
        cat >> "${HTML_REPORT}" <<TABEOF
      <button class="tab-btn${ISSUE_CLASS}" onclick="switchTab(this,'cmp-${PAIR}')">
        ${PAIR} $([ ${MCOUNT} -gt 0 ] && echo "&#9888;${MCOUNT}" || echo "&#10004;")
      </button>
TABEOF
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF8
    </div>
    <!-- OVERVIEW TAB -->
    <div id="cmp-overview" class="tab-content active">
      <h3 style="margin-bottom:16px; color:var(--primary);">Comparison Summary</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Primary DB</th><th>Standby DB</th><th>Mismatches</th><th>Status</th></tr></thead>
          <tbody>
HTMLEOF8

    for DF in $(ls "${BASE_DIR}/reports/diff_"*.csv 2>/dev/null | sort); do
        BASENAME=$(basename "${DF}" .csv | sed 's/^diff_//')
        PRI_DB=$(echo "${BASENAME}" | ${AWK} -F'_vs_' '{print $1}')
        STB_DB=$(echo "${BASENAME}" | ${AWK} -F'_vs_' '{print $2}')
        MCOUNT=$(tail -n +2 "${DF}" | wc -l | tr -d ' ')
        if [ ${MCOUNT} -gt 0 ]; then
            STATUS="<span class='badge badge-mismatch'>&#9888; ${MCOUNT} Mismatch(es)</span>"
        else
            STATUS="<span class='badge badge-match'>&#10004; Identical</span>"
        fi
        cat >> "${HTML_REPORT}" <<ROWEOF
          <tr>
            <td>${PRI_DB}</td>
            <td>${STB_DB}</td>
            <td>${MCOUNT}</td>
            <td>${STATUS}</td>
          </tr>
ROWEOF
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF9
          </tbody>
        </table>
      </div>
    </div>
HTMLEOF9

    # Per-pair detail tabs
    for DF in $(ls "${BASE_DIR}/reports/diff_"*.csv 2>/dev/null | sort); do
        BASENAME=$(basename "${DF}" .csv | sed 's/^diff_//')
        PRI_DB=$(echo "${BASENAME}" | ${AWK} -F'_vs_' '{print $1}')
        STB_DB=$(echo "${BASENAME}" | ${AWK} -F'_vs_' '{print $2}')
        MCOUNT=$(tail -n +2 "${DF}" | wc -l | tr -d ' ')

        cat >> "${HTML_REPORT}" <<PAIREOF
    <div id="cmp-${BASENAME}" class="tab-content">
      <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <h3 style="color:var(--primary);">${PRI_DB} vs ${STB_DB}</h3>
        $([ ${MCOUNT} -gt 0 ] && echo "<span class='badge badge-mismatch'>&#9888; ${MCOUNT} Mismatch(es)</span>" || echo "<span class='badge badge-match'>&#10004; No Mismatches</span>")
      </div>
      <input class="search-bar" type="text" placeholder="Search parameters..." oninput="filterTable(this,'tbl-${BASENAME}')">
PAIREOF

        if [ ${MCOUNT} -eq 0 ]; then
            cat >> "${HTML_REPORT}" <<OKEOF
      <div class="alert alert-success">
        <span class="alert-icon">&#10004;</span>
        <div>All comparable parameters match between <strong>${PRI_DB}</strong> and <strong>${STB_DB}</strong>.</div>
      </div>
OKEOF
        else
            cat >> "${HTML_REPORT}" <<TABLEEOF
      <div class="table-wrap">
        <table id="tbl-${BASENAME}">
          <thead>
            <tr>
              <th>Parameter Name</th>
              <th>Primary Value (${PRI_DB})</th>
              <th>Standby Value (${STB_DB})</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
TABLEEOF
            tail -n +2 "${DF}" | while IFS=',' read PDB SDB PNAME PVAL SVAL STATUS; do
                STATUS_BADGE=""
                case "${STATUS}" in
                    MISMATCH) STATUS_BADGE="<span class='badge badge-mismatch'>Mismatch</span>" ;;
                    MISMATCH_MISSING_STB) STATUS_BADGE="<span class='badge badge-warn'>Missing on Standby</span>" ;;
                    MISMATCH_MISSING_PRI) STATUS_BADGE="<span class='badge badge-warn'>Missing on Primary</span>" ;;
                    *) STATUS_BADGE="<span class='badge badge-match'>${STATUS}</span>" ;;
                esac
                cat >> "${HTML_REPORT}" <<ROWEOF2
            <tr>
              <td>${PNAME}</td>
              <td><span class="val-pri">${PVAL}</span></td>
              <td><span class="val-stb">${SVAL}</span></td>
              <td>${STATUS_BADGE}</td>
            </tr>
ROWEOF2
            done
            cat >> "${HTML_REPORT}" <<TABLEEOF2
          </tbody>
        </table>
      </div>
TABLEEOF2
        fi
        echo "    </div>" >> "${HTML_REPORT}"
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF10
  </div>
</div>

<!-- ===================== RAW DATA ===================== -->
<div id="page-csv-data" class="page-section" style="display:none;">
  <div class="tabs-wrapper">
    <div class="tab-bar" id="raw-tab-bar">
HTMLEOF10

    ALL_DBS=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' '{print $1}' | sort -u)
    FIRST=1
    for DB in ${ALL_DBS}; do
        ACTIVE=""; [ ${FIRST} -eq 1 ] && ACTIVE=" active"
        cat >> "${HTML_REPORT}" <<RAWTABEOF
      <button class="tab-btn${ACTIVE}" onclick="switchTab(this,'raw-${DB}')">${DB}</button>
RAWTABEOF
        FIRST=0
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF11
    </div>
HTMLEOF11

    FIRST=1
    for DB in ${ALL_DBS}; do
        ACTIVE=""; [ ${FIRST} -eq 1 ] && ACTIVE=" active"
        ROLE=$(tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" '$1==d{print $2;exit}')
        cat >> "${HTML_REPORT}" <<RAWCONTEOF
    <div id="raw-${DB}" class="tab-content${ACTIVE}">
      <div style="display:flex; align-items:center; gap:12px; margin-bottom:14px;">
        <h3 style="color:var(--primary);">${DB}</h3>
        <span class="badge $([ "${ROLE}" = "PRIMARY" ] && echo badge-primary || echo badge-standby)">${ROLE}</span>
      </div>
      <input class="search-bar" type="text" placeholder="Search parameters..." oninput="filterTable(this,'rawt-${DB}')">
      <div class="table-wrap">
        <table id="rawt-${DB}">
          <thead><tr><th>Parameter</th><th>Value</th><th>Collected</th></tr></thead>
          <tbody>
RAWCONTEOF
        tail -n +2 "${CSV_FILE}" | ${AWK} -F',' -v d="${DB}" \
            '$1==d {print "<tr><td>"$5"</td><td><code>"$6"</code></td><td>"$4"</td></tr>"}' >> "${HTML_REPORT}"
        cat >> "${HTML_REPORT}" <<RAWEOF
          </tbody>
        </table>
      </div>
    </div>
RAWEOF
        FIRST=0
    done

    cat >> "${HTML_REPORT}" <<HTMLEOF12
  </div>
</div>

</div><!-- /container -->

<div class="footer">
  Oracle DG Parameter Monitor &nbsp;|&nbsp; Generated ${REPORT_TS} &nbsp;|&nbsp; ${HOSTNAME}
</div>

<script>
// Page navigation
function showPage(name) {
  document.querySelectorAll('.page-section').forEach(p => p.style.display='none');
  var pg = document.getElementById('page-'+name);
  if (pg) pg.style.display='block';
  document.querySelectorAll('.nav a').forEach(a => a.classList.remove('active'));
  event.target.classList.add('active');
}

// Tab switching within a section
function switchTab(btn, tabId) {
  var bar = btn.closest('.tab-bar');
  bar.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  var wrapper = bar.closest('.tabs-wrapper');
  wrapper.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  var tab = document.getElementById(tabId);
  if (tab) tab.classList.add('active');
}

// Table search/filter
function filterTable(input, tableId) {
  var filter = input.value.toLowerCase();
  var table = document.getElementById(tableId);
  if (!table) return;
  table.querySelectorAll('tbody tr').forEach(function(row) {
    row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
  });
}
</script>
</body>
</html>
HTMLEOF12

    log_info "HTML report generated: ${HTML_REPORT}"
    echo "${HTML_REPORT}"
}

# =============================================================================
# EMAIL FUNCTION
# =============================================================================

send_email() {
    local REPORT_PATH="$1"
    local MISMATCH_COUNT="$2"

    if [ ! -f "${REPORT_PATH}" ]; then
        log_error "HTML report not found: ${REPORT_PATH}"
        return 1
    fi

    log_info "Sending email to: ${EMAIL_TO} via ${EMAIL_METHOD}..."

    local SUBJ="${EMAIL_SUBJECT}"
    [ "${MISMATCH_COUNT}" -gt 0 ] && SUBJ="[ACTION REQUIRED] ${SUBJ} - ${MISMATCH_COUNT} Mismatch(es)"

    case "${EMAIL_METHOD}" in
        mailx|mail)
            if command -v mailx >/dev/null 2>&1; then
                (
                echo "MIME-Version: 1.0"
                echo "Content-Type: text/html; charset=UTF-8"
                echo ""
                cat "${REPORT_PATH}"
                ) | mailx -s "${SUBJ}" \
                    -r "${EMAIL_FROM}" \
                    "${EMAIL_TO}" 2>/dev/null && \
                log_info "Email sent via mailx" || log_error "mailx failed"
            else
                log_warn "mailx not found, trying mail..."
                mail -s "${SUBJ}" "${EMAIL_TO}" < "${REPORT_PATH}" && \
                log_info "Email sent via mail" || log_error "mail failed"
            fi
            ;;
        sendmail)
            if command -v sendmail >/dev/null 2>&1; then
                (
                echo "To: ${EMAIL_TO}"
                echo "From: ${EMAIL_FROM}"
                echo "Subject: ${SUBJ}"
                echo "MIME-Version: 1.0"
                echo "Content-Type: text/html; charset=UTF-8"
                echo ""
                cat "${REPORT_PATH}"
                ) | sendmail -t && log_info "Email sent via sendmail" || log_error "sendmail failed"
            else
                log_error "sendmail not found"
            fi
            ;;
        mutt)
            if command -v mutt >/dev/null 2>&1; then
                mutt -e "set content_type=text/html" \
                     -s "${SUBJ}" \
                     -a "${REPORT_PATH}" \
                     -- "${EMAIL_TO}" < /dev/null && \
                log_info "Email sent via mutt" || log_error "mutt failed"
            else
                log_error "mutt not found"
            fi
            ;;
        *)
            log_error "Unknown EMAIL_METHOD: ${EMAIL_METHOD}"
            return 1
            ;;
    esac
}

# =============================================================================
# MAIN LOGIC
# =============================================================================

parse_args() {
    for arg in "$@"; do
        case "${arg}" in
            --help|-h) print_usage ;;
            --collect-only) MODE="collect" ;;
            --report|--report-only) MODE="report" ;;
            --force-compare) FORCE_COMPARE=1 ;;
            --debug) DEBUG=1 ;;
            *) log_warn "Unknown argument: ${arg}" ;;
        esac
    done
}

main() {
    parse_args "$@"
    setup_dirs
    setup_os_compat

    log "============================================================"
    log "Oracle DG Parameter Check - Starting (Mode: ${MODE})"
    log "Host: ${HOSTNAME}  OS: ${OS_TYPE}  Date: ${RUN_DATE}"
    log "============================================================"

    # ---- REPORT ONLY MODE ----
    if [ "${MODE}" = "report" ]; then
        log_info "Report-only mode: generating HTML and sending email"
        if [ ! -f "${CSV_FILE}" ]; then
            log_error "CSV file not found: ${CSV_FILE}. Run collection first."
            exit 1
        fi
        REPORT_PATH=$(generate_html_report)
        TOTAL_M=0
        for DF in $(ls "${BASE_DIR}/reports/diff_"*.csv 2>/dev/null); do
            C=$(tail -n +2 "${DF}" | wc -l | tr -d ' ')
            TOTAL_M=$((TOTAL_M+C))
        done
        send_email "${REPORT_PATH}" "${TOTAL_M}"
        log_info "Done."
        exit 0
    fi

    # ---- COLLECTION MODE ----
    INSTANCES=$(get_running_instances)

    if [ -z "${INSTANCES}" ]; then
        log_error "No Oracle instances found running on this host."
        exit 1
    fi

    for SID in ${INSTANCES}; do
        separator
        log_info "Processing instance: ${SID}"

        OH=$(get_oracle_home "${SID}")
        if [ -z "${OH}" ]; then
            log_error "Cannot find ORACLE_HOME for ${SID}, skipping"
            continue
        fi
        log_info "ORACLE_HOME: ${OH}"

        # Set env
        export ORACLE_SID="${SID}"
        export ORACLE_HOME="${OH}"
        export PATH="${OH}/bin:${PATH}"
        export LD_LIBRARY_PATH="${OH}/lib:${LD_LIBRARY_PATH}"

        # Check DG status
        DG_STATUS=$(check_dg_enabled "${SID}" "${OH}")
        log_info "DG status for ${SID}: ${DG_STATUS}"

        if [ "${DG_STATUS}" = "NODG" ]; then
            log_info "No Data Guard configured for ${SID}. Skipping."
            continue
        fi

        # Get role
        DB_ROLE=$(get_db_role "${SID}" "${OH}")
        if [ -z "${DB_ROLE}" ]; then
            log_error "Cannot determine role for ${SID}, skipping"
            continue
        fi
        log_info "Database role: ${DB_ROLE}"

        # Get db names
        DB_NAME_INFO=$(get_db_names "${SID}" "${OH}")
        DB_UNIQUE_NAME=$(echo "${DB_NAME_INFO}" | cut -d'|' -f1 | tr -d ' \r')
        DB_VERSION=$(echo "${DB_NAME_INFO}" | cut -d'|' -f2 | tr -d ' \r')
        PRIMARY_DB_UNIQUE_NAME=$(echo "${DB_NAME_INFO}" | cut -d'|' -f3 | tr -d ' \r')

        if [ -z "${DB_UNIQUE_NAME}" ]; then
            DB_UNIQUE_NAME="${SID}"
            log_warn "Using SID as db_unique_name: ${SID}"
        fi

        # If this is primary, its primary_db is itself
        if echo "${DB_ROLE}" | grep -qi "PRIMARY"; then
            PRIMARY_DB_UNIQUE_NAME="${DB_UNIQUE_NAME}"
        fi

        # If standby and we couldn't get primary name, try dgmgrl
        if echo "${DB_ROLE}" | grep -qi "STANDBY" && \
           ([ -z "${PRIMARY_DB_UNIQUE_NAME}" ] || [ "${PRIMARY_DB_UNIQUE_NAME}" = "UNKNOWN" ]); then
            PRIMARY_DB_UNIQUE_NAME=$(get_primary_via_dgmgrl "${SID}" "${OH}")
            log_info "Primary DB (via dgmgrl): ${PRIMARY_DB_UNIQUE_NAME}"
        fi

        log_info "DB Unique Name: ${DB_UNIQUE_NAME}, Version: ${DB_VERSION}, Primary: ${PRIMARY_DB_UNIQUE_NAME}"

        # Collect parameters
        collect_parameters "${SID}" "${OH}" "${DB_ROLE}" "${DB_UNIQUE_NAME}" \
            "${DB_VERSION}" "${PRIMARY_DB_UNIQUE_NAME}" "${DG_STATUS}"

        # Ensure audit table exists
        create_audit_table "${SID}" "${OH}"

        # ---- SMART COMPARE TRIGGER ----
        if [ "${MODE}" != "collect" ]; then
            EFFECTIVE_PRIMARY="${PRIMARY_DB_UNIQUE_NAME:-${DB_UNIQUE_NAME}}"
            READY=$(should_compare "${EFFECTIVE_PRIMARY}")
            log_info "Ready to compare for primary ${EFFECTIVE_PRIMARY}? ${READY}"

            if [ "${READY}" = "YES" ] || [ "${FORCE_COMPARE:-0}" = "1" ]; then
                log_info "Both primary and standby data available. Running comparison..."
                compare_parameters "${EFFECTIVE_PRIMARY}"

                # Check diff results and write ORA error if mismatches found
                for DF in $(ls "${BASE_DIR}/reports/diff_${EFFECTIVE_PRIMARY}_vs_"*.csv 2>/dev/null); do
                    MCOUNT=$(tail -n +2 "${DF}" | wc -l | tr -d ' ')
                    if [ ${MCOUNT} -gt 0 ]; then
                        STB_NAME=$(basename "${DF}" .csv | sed "s/diff_${EFFECTIVE_PRIMARY}_vs_//")
                        DETAIL="${MCOUNT} parameters differ"
                        write_ora_error "${SID}" "${OH}" "${STB_NAME}" "${DETAIL}"
                    fi
                done
            else
                log_info "Waiting for counterpart data before comparing."
                log_info "  (Run script on the other side of DG to trigger comparison)"
            fi
        fi
    done

    # ---- POST-RUN REPORT (if report mode or if mismatches exist) ----
    if ls "${BASE_DIR}/reports/diff_"*.csv >/dev/null 2>&1; then
        TOTAL_M=0
        for DF in $(ls "${BASE_DIR}/reports/diff_"*.csv 2>/dev/null); do
            C=$(tail -n +2 "${DF}" | wc -l | tr -d ' ')
            TOTAL_M=$((TOTAL_M+C))
        done

        if [ ${TOTAL_M} -gt 0 ]; then
            log_warn "SUMMARY: ${TOTAL_M} total parameter mismatch(es) found. Generating report..."
            generate_html_report
            send_email "${HTML_REPORT}" "${TOTAL_M}"
        else
            log_info "SUMMARY: No parameter mismatches found."
            generate_html_report  # still generate for record-keeping
        fi
    fi

    # Clean up old logs
    find "${BASE_DIR}/logs" -name "*.log" -mtime +${LOG_RETENTION_DAYS} -exec rm -f {} \; 2>/dev/null

    separator
    log_info "Oracle DG Parameter Check complete."
    log "============================================================"
}

main "$@"
