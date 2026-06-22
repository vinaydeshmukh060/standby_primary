#!/bin/sh
# ==============================================================================
# Script: compare_dg_params.sh
# Purpose: Compare Oracle Primary and Standby parameters, generate CSV/HTML, 
#          and alert on differences. Compatible with Linux and Solaris.
# ==============================================================================

# --- Configuration Variables ---
BASE_DIR="/path/to/shared/mount" # MUST BE A SHARED DIRECTORY FOR BOTH NODES
CSV_FILE="$BASE_DIR/dg_parameters.csv"
HTML_FILE="$BASE_DIR/dg_param_report.html"
EXCLUDE_FILE="$BASE_DIR/exclude_params.txt"
LOG_FILE="$BASE_DIR/param_compare.log"
MAIL_TO="dba_team@yourdomain.com"
SEND_MAIL="N"

# --- Parse Arguments ---
while getopts "m" opt; do
  case $opt in
    m) SEND_MAIL="Y" ;;
    *) echo "Usage: $0 [-m] (Use -m to send email report)" ; exit 1 ;;
  esac
done

# --- Determine OS for specific commands ---
OS=$(uname -s)
if [ "$OS" = "SunOS" ]; then
    AWK_CMD="nawk" # Solaris usually requires nawk for advanced text processing
    ORATAB="/var/opt/oracle/oratab"
else
    AWK_CMD="awk"
    ORATAB="/etc/oratab"
fi

log_msg() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }

# Initialize CSV if it doesn't exist
[ ! -f "$CSV_FILE" ] && echo "DB_NAME,DB_UNIQUE_NAME,ROLE,PARAM_NAME,PARAM_VALUE" > "$CSV_FILE"
[ ! -f "$EXCLUDE_FILE" ] && touch "$EXCLUDE_FILE"

# --- Function: Generate HTML Report ---
generate_html() {
    log_msg "Generating HTML Report..."
    
    # HTML Header with CSS and JavaScript for Tabs
    cat << 'EOF' > "$HTML_FILE"
<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 20px; }
  h2 { color: #333; }
  .tab { overflow: hidden; border: 1px solid #ccc; background-color: #e2e2e2; }
  .tab button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; font-size: 16px; font-weight: bold;}
  .tab button:hover { background-color: #ddd; }
  .tab button.active { background-color: #fff; border-bottom: 2px solid #0056b3; }
  .tabcontent { display: none; padding: 20px; border: 1px solid #ccc; border-top: none; background-color: #fff; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; }
  th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
  th { background-color: #0056b3; color: white; }
  .diff-row { background-color: #ffcccc; }
</style>
<script>
function openDB(evt, dbName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) { tabcontent[i].style.display = "none"; }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) { tablinks[i].className = tablinks[i].className.replace(" active", ""); }
  document.getElementById(dbName).style.display = "block";
  evt.currentTarget.className += " active";
}
</script>
</head>
<body>
<h2>Data Guard Parameter Comparison Report</h2>
<div class="tab">
  <button class="tablinks active" onclick="openDB(event, 'Landing')">Index / Landing Page</button>
EOF

    # Get distinct DB_NAMEs that have BOTH Primary and Standby entries
    DB_LIST=$($AWK_CMD -F, 'NR>1 {a[$1][$3]=1} END {for (i in a) if (a[i]["PRIMARY"]==1 && a[i]["PHYSICAL STANDBY"]==1) print i}' "$CSV_FILE")

    for DBNAME in $DB_LIST; do
        echo "  <button class=\"tablinks\" onclick=\"openDB(event, '$DBNAME')\">$DBNAME</button>" >> "$HTML_FILE"
    done
    echo "</div>" >> "$HTML_FILE"

    # Landing Page Content
    echo "<div id=\"Landing\" class=\"tabcontent\" style=\"display:block;\"><h3>Databases Monitored</h3><ul>" >> "$HTML_FILE"
    for DBNAME in $DB_LIST; do echo "<li>$DBNAME</li>" >> "$HTML_FILE"; done
    echo "</ul><p>Select a database tab above to view parameter differences.</p></div>" >> "$HTML_FILE"

    # Generate Tabs for each DB
    for DBNAME in $DB_LIST; do
        echo "<div id=\"$DBNAME\" class=\"tabcontent\"><h3>Differences for $DBNAME</h3>" >> "$HTML_FILE"
        echo "<table><tr><th>Parameter</th><th>Primary Value</th><th>Standby Value</th></tr>" >> "$HTML_FILE"
        
        # Compare logic using awk
        $AWK_CMD -F, -v db="$DBNAME" '
            $1 == db {
                if ($3 == "PRIMARY") prim[$4]=$5;
                if ($3 == "PHYSICAL STANDBY") stdby[$4]=$5;
            }
            END {
                for (p in prim) {
                    if (prim[p] != stdby[p] && stdby[p] != "") {
                        print "<tr class=\"diff-row\"><td>"p"</td><td>"prim[p]"</td><td>"stdby[p]"</td></tr>"
                    }
                }
            }
        ' "$CSV_FILE" >> "$HTML_FILE"
        
        echo "</table></div>" >> "$HTML_FILE"
    done

    echo "</body></html>" >> "$HTML_FILE"
    log_msg "HTML Report generated at $HTML_FILE"

    if [ "$SEND_MAIL" = "Y" ]; then
        log_msg "Sending email report..."
        # Note: mailx syntax for HTML varies. This uses standard sendmail format.
        (
            echo "To: $MAIL_TO"
            echo "Subject: Database Parameter Comparison Report"
            echo "Content-Type: text/html"
            echo ""
            cat "$HTML_FILE"
        ) | sendmail -t
    fi
}

# --- Main Logic: Find PMONs and Process ---
# Fetch running pmon processes, exclude ASM, APX, MGMT
ps -ef | grep pmon | grep -v grep | egrep -v "ASM|APX|MGMT" | while read -r line; do
    # Extract SID
    SID=$(echo "$line" | $AWK_CMD '{print $NF}' | sed 's/ora_pmon_//g')
    export ORACLE_SID=$SID
    
    # Determine ORACLE_HOME from oratab
    OH=$(grep "^${SID}:" "$ORATAB" | cut -d: -f2)
    if [ -z "$OH" ]; then
        # Try finding by stripping RAC node number
        BASE_SID=$(echo "$SID" | sed 's/[0-9]*$//')
        OH=$(grep "^${BASE_SID}:" "$ORATAB" | cut -d: -f2)
    fi
    
    if [ -z "$OH" ]; then
        log_msg "Could not determine ORACLE_HOME for $SID. Skipping."
        continue
    fi
    export ORACLE_HOME=$OH
    export PATH=$ORACLE_HOME/bin:$PATH

    log_msg "Processing Instance: $ORACLE_SID"

    # Gather DB Info via SQL*Plus
    DB_INFO=$($ORACLE_HOME/bin/sqlplus -s / as sysdba <<EOF
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 300
SELECT db_unique_name || '|' || database_role || '|' || name FROM v\$database;
EXIT;
EOF
)
    
    DB_UNIQUE_NAME=$(echo "$DB_INFO" | cut -d'|' -f1 | tr -d ' ')
    ROLE=$(echo "$DB_INFO" | cut -d'|' -f2 | tr -d ' ')
    DB_NAME=$(echo "$DB_INFO" | cut -d'|' -f3 | tr -d ' ')

    # Check DG Broker if Primary
    if [ "$ROLE" = "PRIMARY" ]; then
        DG_START=$($ORACLE_HOME/bin/sqlplus -s / as sysdba <<EOF
SET HEAD OFF FEEDBACK OFF PAGES 0
SELECT value FROM v\$parameter WHERE name = 'dg_broker_start';
EXIT;
EOF
)
        if [ "$(echo "$DG_START" | tr -d ' ' | tr '[a-z]' '[A-Z]')" != "TRUE" ]; then
            log_msg "$DB_UNIQUE_NAME is Primary but dg_broker_start is not TRUE. Skipping."
            continue
        fi
        
        # Double check with dgmgrl (Optional, but requested)
        DGMGRL_CHECK=$(dgmgrl / "show configuration" | grep -i "Configuration -")
        if [ -z "$DGMGRL_CHECK" ]; then
            log_msg "$DB_UNIQUE_NAME Data Guard not configured in DGMGRL. Skipping."
            continue
        fi
    fi

    # Format Exclude List for SQL IN clause
    EXCLUDE_LIST=$(awk '{print "''" $0 "''"}' "$EXCLUDE_FILE" | paste -sd, -)
    [ -z "$EXCLUDE_LIST" ] && EXCLUDE_LIST="'NO_EXCLUSIONS_DUMMY'"

    # Extract Parameters
    TMP_PARAM_FILE="/tmp/params_${DB_UNIQUE_NAME}.txt"
    $ORACLE_HOME/bin/sqlplus -s / as sysdba <<EOF > "$TMP_PARAM_FILE"
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 COLSEP ','
SELECT '$DB_NAME', '$DB_UNIQUE_NAME', '$ROLE', name, value 
FROM v\$system_parameter 
WHERE isdefault = 'FALSE' 
  AND name NOT IN ($EXCLUDE_LIST);
EXIT;
EOF

    # Clean CSV: Remove old entries for this DB_UNIQUE_NAME to prevent duplicates
    grep -v ",${DB_UNIQUE_NAME}," "$CSV_FILE" > "${CSV_FILE}.tmp"
    mv "${CSV_FILE}.tmp" "$CSV_FILE"
    
    # Append new data (ignoring blank lines)
    grep -v "^$" "$TMP_PARAM_FILE" >> "$CSV_FILE"
    rm "$TMP_PARAM_FILE"

    log_msg "Updated CSV for $DB_UNIQUE_NAME ($ROLE)"

    # --- Intelligence: Check if we should Compare ---
    # Does the CSV now have both Primary and Standby for this DB_NAME?
    HAS_PRIMARY=$(grep "^${DB_NAME}," "$CSV_FILE" | grep ",PRIMARY," | wc -l)
    HAS_STANDBY=$(grep "^${DB_NAME}," "$CSV_FILE" | grep ",PHYSICAL STANDBY," | wc -l)

    if [ "$HAS_PRIMARY" -gt 0 ] && [ "$HAS_STANDBY" -gt 0 ]; then
        log_msg "Both Primary and Standby data exist for $DB_NAME. Running comparison..."
        
        # Check for differences
        DIFF_COUNT=$($AWK_CMD -F, -v db="$DB_NAME" '
            $1 == db {
                if ($3 == "PRIMARY") prim[$4]=$5;
                if ($3 == "PHYSICAL STANDBY") stdby[$4]=$5;
            }
            END {
                count=0;
                for (p in prim) {
                    if (prim[p] != stdby[p] && stdby[p] != "") count++;
                }
                print count;
            }
        ' "$CSV_FILE")

        if [ "$DIFF_COUNT" -gt 0 ]; then
            log_msg "Differences found ($DIFF_COUNT parameters) for $DB_NAME. Injecting ORA error..."
            
            # Write ORA error to Alert Log WITHOUT creating database objects
            $ORACLE_HOME/bin/sqlplus -s / as sysdba <<EOF
BEGIN
  SYS.DBMS_SYSTEM.KSDWRT(2, 'ORA-20999: Data Guard Parameter Mismatch detected for $DB_NAME. Check HTML Report.');
END;
/
EXIT;
EOF
        else
            log_msg "No parameter differences found for $DB_NAME."
        fi
        
        # Generate the report since a comparison was triggered
        generate_html
    else
        log_msg "Waiting for counterpart instance to run for $DB_NAME to perform comparison."
    fi

done

log_msg "Execution Completed."
