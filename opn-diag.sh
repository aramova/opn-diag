#!/usr/local/bin/bash

# OPNsense Comprehensive Diagnostics Collector Script
# - Refactored with functions for each section
# - Each function handles its own output redirection for better control
# - Step duration measurement for each section/major command
# - Cooldowns after potentially long-running tasks
# - MD5/SHA256 hash of the output file saved to separate files
# - Safer integer comparisons for ping stats
# - Lines formatted to a maximum of 80 characters
# - Shebang updated to bash and case statements fixed for bash
# - Added ARP timeout section
# - Modified tcpdump to exclude common web traffic
# - Removed "Console" prefix from TTY output
# - Added cumulative time for each diagnostic section
# - Renamed section functions and made section numbering dynamic
# - Added Index of Sections to output file
# - Switched to direct dmidecode calls for system & bios info
# - Improved robustness of WAN gateway parsing
# - Fixed label logging in execute_cmd and skipped messages
# - Fixed ping6 illegal option -X
# - Fixed WAN Gateway ping by making -S flag conditional
# - Changed opnsense-log filter to use head for line limiting (v0.50.7)

SCRIPT_VERSION="v0.50.7"
OUTPUT_FILE="opnsense_diagnostics_output_$(date +%Y%m%d_%H%M%S).txt"
DIVIDER_MAJOR="================================================================================"
DIVIDER_MINOR="--------------------------------------------------------------------------------"
COOLDOWN_SECONDS=1 # Seconds to pause after certain long-running commands

# Define command paths
OPNSENSE_VERSION_CMD="/usr/local/sbin/opnsense-version"
OPNSENSE_LOG_CMD="/usr/local/sbin/opnsense-log"
OPNSENSE_UPDATE_CMD="/usr/local/sbin/opnsense-update"
CONFIGCTL_CMD="/usr/local/sbin/configctl"
OPNSENSE_BOOTSTRAP_CMD="/usr/local/sbin/opnsense-bootstrap"
DMIDECODE_CMD="/usr/local/sbin/dmidecode"

# Paths for hardware diagnostic tools (common locations)
LSCPU_CMD="/usr/local/bin/lscpu"
LSBLK_CMD="/usr/local/bin/lsblk"
HWSTAT_CMD_S="/usr/local/sbin/hwstat"
HWSTAT_CMD_L_B="/usr/local/bin/hwstat"
SMARTCTL_CMD="/usr/local/sbin/smartctl"
DRILL_CMD="/usr/local/bin/drill"
MTR_CMD="/usr/local/sbin/mtr"

ACTUAL_HWSTAT_CMD=""
if [ -x "$HWSTAT_CMD_S" ]; then
    ACTUAL_HWSTAT_CMD="$HWSTAT_CMD_S"
elif [ -x "$HWSTAT_CMD_L_B" ]; then
    ACTUAL_HWSTAT_CMD="$HWSTAT_CMD_L_B"
fi

# Global counters
STEP_NUM=0
SECTION_NUM=0 

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root." >&2
  echo "Please use 'sudo sh ./your_script_name.sh' or 'bash ./your_script_name.sh'" >&2
  exit 1
fi

# Function to initialize the output file
initialize_output_file() {
    echo "OPNsense Comprehensive Diagnostics Collection ($SCRIPT_VERSION)" \
        > "$OUTPUT_FILE"
    echo "Date: $(date)" >> "$OUTPUT_FILE"
    echo "Hostname: $(hostname)" >> "$OUTPUT_FILE"
    if [ -x "$OPNSENSE_VERSION_CMD" ]; then
        echo "OPNsense Version (opnsense-version -n): " \
             "$($OPNSENSE_VERSION_CMD -n)" >> "$OUTPUT_FILE"
        echo "OPNsense Version (opnsense-version): " \
             "$($OPNSENSE_VERSION_CMD)" >> "$OUTPUT_FILE"
    else
        echo "OPNsense Version: $OPNSENSE_VERSION_CMD not found or not executable." \
            >> "$OUTPUT_FILE"
    fi
    echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

# Function for initial permission checks (TTY and file)
perform_initial_checks() {
    echo "Starting OPNsense Comprehensive Diagnostics Collection ($SCRIPT_VERSION)."
    echo "Output will be saved to: $OUTPUT_FILE"
    echo "This may take a few minutes..."
    echo "$DIVIDER_MAJOR" 

    echo "Checking for OPNsense & Diagnostic utilities:"
    CMD_PATHS_TO_CHECK=("$OPNSENSE_VERSION_CMD" "$OPNSENSE_LOG_CMD" \
"$OPNSENSE_UPDATE_CMD" "$CONFIGCTL_CMD" "$OPNSENSE_BOOTSTRAP_CMD" "$LSCPU_CMD" \
"$LSBLK_CMD" "$SMARTCTL_CMD" "$HWSTAT_CMD_S" "$HWSTAT_CMD_L_B" "$DRILL_CMD" \
"$MTR_CMD" "$DMIDECODE_CMD")

    for cmd_path_check in "${CMD_PATHS_TO_CHECK[@]}"; do
        if [ -n "$cmd_path_check" ]; then
            if [ -e "$cmd_path_check" ]; then ls -l "$cmd_path_check"; else echo "$cmd_path_check does not exist."; fi
        fi
    done
    if [ ! -x "$CONFIGCTL_CMD" ]; then echo "$CONFIGCTL_CMD not found or not executable."; fi
    if command -v jq >/dev/null 2>&1; then
        echo "jq version: $(jq --version)"
    else
        echo "jq utility not found. Some parsing might be limited."
    fi
    echo "$DIVIDER_MAJOR"
    echo "Continuing collection, all further output will be in $OUTPUT_FILE"
    echo "(Progress will be shown on TTY with step numbers)"

    echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "Checking for OPNsense & Diagnostic utilities (logged to file):" >> "$OUTPUT_FILE"
    echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    for cmd_path_check in "${CMD_PATHS_TO_CHECK[@]}"; do
        if [ -n "$cmd_path_check" ]; then
            if [ -e "$cmd_path_check" ]; then ls -l "$cmd_path_check" >> "$OUTPUT_FILE" 2>&1; else echo "$cmd_path_check does not exist." >> "$OUTPUT_FILE"; fi
        fi
    done
    if [ ! -x "$CONFIGCTL_CMD" ]; then echo "$CONFIGCTL_CMD not found or not executable (logged to file)." >> "$OUTPUT_FILE"; fi
    if command -v jq >/dev/null 2>&1; then
        echo "jq version: $(jq --version)" >> "$OUTPUT_FILE"
    else
        echo "jq utility not found. Some parsing might be limited." >> "$OUTPUT_FILE"
    fi
    echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

execute_cmd() {
  local CMD_STRING=$1 LABEL=$2 APPLY_COOLDOWN=$3
  local cmd_status start_time end_time duration
  STEP_NUM=$((STEP_NUM + 1))
  printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL" > /dev/tty
  start_time=$(date +%s)
  echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
  # Quote LABEL for file output to preserve spaces
  echo "COMMAND (File Step $STEP_NUM): \"$LABEL\"" >> "$OUTPUT_FILE"
  echo "Actual command: $CMD_STRING" >> "$OUTPUT_FILE"
  echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
  eval "$CMD_STRING" >> "$OUTPUT_FILE" 2>&1; cmd_status=$?
  end_time=$(date +%s); duration=$((end_time - start_time))
  echo "Duration: ${duration}s. Exit status: $cmd_status" >> "$OUTPUT_FILE"
  printf "Step %3d: Finished %s in %ds. Status: %d.\n" "$STEP_NUM" "$LABEL" "$duration" "$cmd_status" > /dev/tty
  if [ "$APPLY_COOLDOWN" = "cooldown" ]; then
      printf "Step %3d: Pausing for %d seconds after %s...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" "$LABEL" > /dev/tty
      sleep "$COOLDOWN_SECONDS"
  fi
  echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

execute_if_binary_exists() {
  local CMD_PATH=$1 CMD_ARGS=$2 LABEL=$3 APPLY_COOLDOWN=$4
  local suggestion cmd_status start_time end_time duration full_command=()
  STEP_NUM=$((STEP_NUM + 1))
  if [ -x "$CMD_PATH" ]; then
    printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL" > /dev/tty
    start_time=$(date +%s)
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    # Quote LABEL for file output
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL\"" >> "$OUTPUT_FILE"
    echo "Actual command: $CMD_PATH $CMD_ARGS" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    full_command+=("$CMD_PATH")
    if [ -n "$CMD_ARGS" ]; then read -r -a temp_args <<< "$CMD_ARGS"; full_command+=("${temp_args[@]}"); fi
    "${full_command[@]}" >> "$OUTPUT_FILE" 2>&1; cmd_status=$?
    end_time=$(date +%s); duration=$((end_time - start_time))
    echo "Duration: ${duration}s. Exit status: $cmd_status" >> "$OUTPUT_FILE"
    printf "Step %3d: Finished %s in %ds. Status: %d.\n" "$STEP_NUM" "$LABEL" "$duration" "$cmd_status" > /dev/tty
    if [ "$APPLY_COOLDOWN" = "cooldown" ]; then
        printf "Step %3d: Pausing for %d seconds after %s...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" "$LABEL" > /dev/tty
        sleep "$COOLDOWN_SECONDS"
    fi
  else
    suggestion=""; case "$CMD_PATH" in
        "$LSCPU_CMD"|"$LSBLK_CMD") suggestion=" (consider 'pkg install sysinfo')" ;;
        "$HWSTAT_CMD_S"|"$HWSTAT_CMD_L_B") suggestion=" (check if hwstat package is installed)" ;;
        "$DRILL_CMD") suggestion=" (consider 'pkg install ldns')" ;;
        "$MTR_CMD") suggestion=" (consider 'pkg install mtr-nox11')" ;;
        "$DMIDECODE_CMD") suggestion=" (consider 'pkg install dmidecode')" ;;
    esac
    printf "Step %3d: Skipping: %s (binary %s not found %s)%s...\n" "$STEP_NUM" "$LABEL" "$CMD_PATH" "or not executable" "$suggestion" > /dev/tty
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    # Quote LABEL for file output
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL\" (SKIPPED - $CMD_PATH not found or not executable)$suggestion" >> "$OUTPUT_FILE"
    echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
  fi
  echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

cat_if_exists() {
    local FILE_PATH=$1
    local LABEL="Content of $FILE_PATH" 
    if [ -f "$FILE_PATH" ] && [ -r "$FILE_PATH" ]; then
        execute_cmd "cat \"$FILE_PATH\"" "$LABEL" 
    else
        STEP_NUM=$((STEP_NUM + 1))
        printf "Step %3d: Skipping: %s (File not found: %s)...\n" "$STEP_NUM" "$LABEL" "$FILE_PATH" > /dev/tty
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        # Use direct string construction for the label in the skipped message
        echo "COMMAND (File Step $STEP_NUM): Content of $FILE_PATH (SKIPPED - File not found or not readable: $FILE_PATH)" >> "$OUTPUT_FILE"
        echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
}

collect_system_info() {
    execute_cmd "uname -a" "Get System Name (uname -a)"
    execute_cmd "freebsd-version -ukr" "Get FreeBSD Version"
    execute_cmd "uptime" "Get System Uptime"
    cat_if_exists "/var/run/dmesg.boot"
    execute_if_binary_exists "$CONFIGCTL_CMD" "system status" "Get OPNsense System Status (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "system sensors" "Get System Sensors (configctl)"
}

collect_hardware_diagnostics() {
    local LABEL_SMART start_time_block end_time_block duration_block DISKS disk
    execute_if_binary_exists "$LSCPU_CMD" "" "Get CPU Info (lscpu)"
    execute_if_binary_exists "$LSBLK_CMD" "" "List Block Devices (lsblk)"
    if [ -n "$ACTUAL_HWSTAT_CMD" ]; then
        execute_if_binary_exists "$ACTUAL_HWSTAT_CMD" "" "Get Hardware Status (hwstat)"
    else
        STEP_NUM=$((STEP_NUM + 1)); printf "Step %3d: Skipping hwstat (not found)...\n" "$STEP_NUM" > /dev/tty
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        echo "COMMAND (File Step $STEP_NUM): \"hwstat\" (SKIPPED - not found at $HWSTAT_CMD_S or $HWSTAT_CMD_L_B)" >> "$OUTPUT_FILE"
        echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
    execute_if_binary_exists "$DMIDECODE_CMD" "-q -t system" "DMIdecode System Info (dmidecode -q -t system)"
    execute_if_binary_exists "$DMIDECODE_CMD" "-q -t bios" "DMIdecode BIOS Info (dmidecode -q -t bios)"
    execute_cmd "geom disk list" "List Disks (geom disk list)"
    STEP_NUM=$((STEP_NUM + 1)); LABEL_SMART="SMARTCTL Diagnostics for Disks"
    printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL_SMART" > /dev/tty
    start_time_block=$(date +%s)
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL_SMART\" (Block Start)" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    if [ -x "$SMARTCTL_CMD" ]; then
        DISKS=$(sysctl -n kern.disks | tr ' ' '\n' | grep -E '^(ada|da|nvme[0-9]+ns[0-9]+|mmcsd[0-9]+|vtbd[0-9]+)')
        if [ -n "$DISKS" ]; then
            for disk in $DISKS; do
                printf "Step %3d:   Getting SMART info for /dev/%s\n" "$STEP_NUM" "$disk" > /dev/tty
                echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "SMART Information for /dev/$disk:" >> "$OUTPUT_FILE"
                "$SMARTCTL_CMD" -a "/dev/$disk" >> "$OUTPUT_FILE" 2>&1
                echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "SMART Health Status for /dev/$disk:" >> "$OUTPUT_FILE"
                "$SMARTCTL_CMD" -H "/dev/$disk" >> "$OUTPUT_FILE" 2>&1; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
            done
        else echo "No suitable disk devices for SMART diagnostics." >> "$OUTPUT_FILE"; fi
    else echo "SKIPPED - $SMARTCTL_CMD not found or not exec." >> "$OUTPUT_FILE"; fi
    end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
    echo "Duration for $LABEL_SMART: ${duration_block}s" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    printf "Step %3d: Finished %s in %ds.\n" "$STEP_NUM" "$LABEL_SMART" "$duration_block" > /dev/tty
    printf "Step %3d: Pausing for %d seconds after %s...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" "$LABEL_SMART" > /dev/tty
    sleep "$COOLDOWN_SECONDS"
}

collect_interface_config() {
    execute_cmd "ifconfig -a -vv" "Full Interface Details (ifconfig -a -vv)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list ifconfig" "Interface List (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface show interfaces" "Interface Summary (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list stats" "Interface Stats (configctl)"
    execute_cmd "netstat -i -n -d -h -W" "Network Interface Statistics (netstat -indhW)"
    execute_cmd "dmesg -a | tail -n 500" "Recent Kernel Messages (dmesg)" "cooldown"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface show carp" "CARP Status (configctl)"
}

collect_routing_arp() {
    execute_cmd "netstat -r -n -A -W" "Routing Tables (netstat -rnAW)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface routes list" "Routes List (configctl)"
    execute_cmd "netstat -rs" "Routing Statistics (netstat -rs)"
    execute_cmd "arp -a -n" "ARP Table (arp -an)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list arp" "ARP List (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list ndp" "NDP List (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface gateways status" "Gateway Status (configctl)"
}

collect_arp_timeouts() {
    execute_cmd "sysctl net.link.ether.inet" "ARP System Configuration (sysctl net.link.ether.inet)"
}

collect_dns_resolution() {
    local LABEL_LOCAL_ZONES start_time_block LOCAL_ZONES_OUTPUT IFS_OLD_DRILL
    local zone_line zone_to_test end_time_block duration_block
    cat_if_exists "/etc/resolv.conf"
    execute_if_binary_exists "$CONFIGCTL_CMD" "system list nameservers" "Configured Nameservers (configctl)"
    execute_cmd "pgrep -lf unbound" "Check Unbound Processes"; execute_cmd "pgrep -lf dnsmasq" "Check Dnsmasq Processes"
    execute_if_binary_exists "$CONFIGCTL_CMD" "unbound status" "Unbound Status (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "dnsmasq status" "Dnsmasq Status (configctl)"
    execute_cmd "service unbound status" "Unbound Service Status (service)"; execute_cmd "service dnsmasq status" "Dnsmasq Service Status (service)"
    execute_cmd "sockstat -4 -6 -l | grep ':53'" "Sockets on Port 53"
    if pgrep -q unbound; then
      if command -v unbound-control >/dev/null 2>&1 && unbound-control status 2>/dev/null; then
        execute_cmd "unbound-control status" "Unbound Control Status"; execute_cmd "unbound-control stats_noreset" "Unbound Control Stats"
      else
        STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping unbound-control (inactive)...\n" "$STEP_NUM" > /dev/tty
        echo "$DIVIDER_MINOR\nCOMMAND (File Step $STEP_NUM): \"unbound-control\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
      fi
      execute_if_binary_exists "$CONFIGCTL_CMD" "unbound stats" "Unbound Stats (configctl)"
    else
        STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping Unbound stats (not running)...\n" "$STEP_NUM" > /dev/tty
        echo "$DIVIDER_MINOR\nCOMMAND (File Step $STEP_NUM): \"Unbound specific stats\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
    execute_if_binary_exists "$DRILL_CMD" "-V 4 google.com" "Drill google.com"
    execute_if_binary_exists "$DRILL_CMD" "-V 4 $(hostname)" "Drill Local Hostname"
    if [ -x "$CONFIGCTL_CMD" ] && [ -x "$DRILL_CMD" ]; then
        STEP_NUM=$((STEP_NUM + 1)); LABEL_LOCAL_ZONES="Testing Local Unbound Zones with drill"
        printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL_LOCAL_ZONES" > /dev/tty; start_time_block=$(date +%s)
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        echo "COMMAND (File Step $STEP_NUM): \"$LABEL_LOCAL_ZONES\" (via configctl unbound listlocalzones)" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        LOCAL_ZONES_OUTPUT=$($CONFIGCTL_CMD unbound listlocalzones 2>/dev/null)
        if [ -n "$LOCAL_ZONES_OUTPUT" ]; then
            echo "Local zones reported:" >> "$OUTPUT_FILE"; echo "$LOCAL_ZONES_OUTPUT" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
            IFS_OLD_DRILL="$IFS"; IFS=$'\n'
            for zone_line in $LOCAL_ZONES_OUTPUT; do
                zone_to_test=$(echo "$zone_line"|awk '{print $1}'|sed 's/\.$//')
                if [ -n "$zone_to_test" ]; then
                    printf "Step %3d:   Drilling local zone: %s\n" "$STEP_NUM" "$zone_to_test" > /dev/tty
                    echo "Drilling local zone: $zone_to_test" >> "$OUTPUT_FILE"
                    "$DRILL_CMD" -V 4 "$zone_to_test" >> "$OUTPUT_FILE" 2>&1; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
                fi
            done; IFS="$IFS_OLD_DRILL"
        else echo "No local zones by 'configctl unbound listlocalzones'." >> "$OUTPUT_FILE"; fi
        end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
        echo "Duration for Local Zone Drill block: ${duration_block}s" >> "$OUTPUT_FILE"
        printf "Step %3d: Finished %s in %ds.\n" "$STEP_NUM" "$LABEL_LOCAL_ZONES" "$duration_block" > /dev/tty
        echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    else
        STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping dynamic local zone drill...\n" "$STEP_NUM" > /dev/tty
        echo "$DIVIDER_MINOR\nCOMMAND (File Step $STEP_NUM): \"Dynamic Local Zone Drill\" (SKIPPED)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
}

collect_firewall_pf_diagnostics() {
    execute_cmd "pfctl -s rules -vv" "PF Rules (pfctl -s rules -vv)"
    execute_cmd "pfctl -s nat -vv" "PF NAT Rules (pfctl -s nat -vv)"
    execute_cmd "echo 'Firewall States (first 500 lines):'; pfctl -s states -vv | head -n 500" "PF States (Top 500)" "cooldown"
    execute_if_binary_exists "$CONFIGCTL_CMD" "filter list states -n 500" "PF States (configctl, Top 500)"
    execute_cmd "pfctl -s info -vv" "PF Info (pfctl -s info -vv)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "filter diag info" "PF Info (configctl)"
    execute_cmd "pfctl -s Tables -vv" "PF Tables (pfctl -s Tables -vv)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "filter list tables" "PF Tables (configctl)"
}

collect_net_connections() {
    execute_cmd "netstat -an -A" "All Network Sockets (netstat -anA)"
    execute_cmd "netstat -ss" "Network Statistics by Protocol (netstat -ss)"
    execute_cmd "sockstat -4 -6 -c -l -u" "Socket Status (sockstat)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface dump sockstat" "Socket Dump (configctl)"
    execute_cmd "netstat -m" "Mbuf Usage (netstat -m)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "system show mbuf" "Mbuf Usage (configctl)"
    execute_cmd "vmstat -i" "Interrupt Statistics (vmstat -i)"
}

collect_system_logs() {
    execute_if_binary_exists "$OPNSENSE_LOG_CMD" "system --lines 200" "OPNsense System Log (Last 200)"
    # Use execute_cmd with head for filter log as --lines might be unreliable
    if [ -x "$OPNSENSE_LOG_CMD" ]; then
        execute_cmd "$OPNSENSE_LOG_CMD filter | head -n 200" "OPNsense Filter Log (Last 200)"
    else
        # This specific log will be skipped if opnsense-log is missing,
        # perform_initial_checks would have noted the binary's absence.
        STEP_NUM=$((STEP_NUM + 1))
        printf "Step %3d: Skipping OPNsense Filter Log (%s not found)...\n" "$STEP_NUM" "$OPNSENSE_LOG_CMD" > /dev/tty
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        echo "COMMAND (File Step $STEP_NUM): \"OPNsense Filter Log (Last 200)\" (SKIPPED - $OPNSENSE_LOG_CMD not found)" >> "$OUTPUT_FILE"
        echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
    execute_if_binary_exists "$OPNSENSE_LOG_CMD" "routing --lines 100" "OPNsense Routing Log (Last 100)"
    execute_if_binary_exists "$OPNSENSE_LOG_CMD" "resolver --lines 100" "OPNsense Resolver Log (Last 100)"
    execute_if_binary_exists "$OPNSENSE_LOG_CMD" "dhcpd --lines 100" "OPNsense DHCPd Log (Last 100)"
    execute_if_binary_exists "$OPNSENSE_LOG_CMD" "ntpd --lines 100" "OPNsense NTPd Log (Last 100)"
    execute_if_binary_exists "$OPNSENSE_LOG_CMD" "chrony --lines 100" "OPNsense Chrony Log (Last 100)"
}

perform_connectivity_tests_general() {
    execute_cmd "ping -c 5 8.8.8.8" "Ping 8.8.8.8"; execute_cmd "ping -c 5 1.1.1.1" "Ping 1.1.1.1"
    execute_cmd "traceroute -n -w 1 8.8.8.8" "Traceroute to 8.8.8.8"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface traceroute 8.8.8.8" "Traceroute via configctl"
    execute_if_binary_exists "$MTR_CMD" "-rwc 5 8.8.8.8" "MTR to 8.8.8.8"
}

capture_tcpdump_non_web() {
    local LABEL_TCPDUMP_BLOCK start_time_block TCPDUMP_IFACE WAN_IFACE_DETAILS
    local DEFAULT_ROUTE_IFACE CMD_STR end_time_block duration_block tcpdump_label
    STEP_NUM=$((STEP_NUM + 1)); LABEL_TCPDUMP_BLOCK="TCPDump Non-Web Traffic Capture Block"
    printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL_TCPDUMP_BLOCK" > /dev/tty; start_time_block=$(date +%s)
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL_TCPDUMP_BLOCK\" (Block Start)" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "Determining interface for tcpdump..." >> "$OUTPUT_FILE"; TCPDUMP_IFACE="any"; WAN_IFACE_DETAILS=""
    if [ -x "$CONFIGCTL_CMD" ]; then
        WAN_IFACE_DETAILS=$("$CONFIGCTL_CMD" interface show interfaces 2>/dev/null | jq -r '.statistics.interface[] | select(.name=="wan") | .device' 2>/dev/null || "$CONFIGCTL_CMD" interface show interfaces 2>/dev/null | grep '"name":"wan"' -A 10 | grep '"device":' | head -n1 | sed -E 's/.*"device": "([^"]+)".*/\1/')
        if [ -n "$WAN_IFACE_DETAILS" ]; then TCPDUMP_IFACE="$WAN_IFACE_DETAILS"; echo "Using WAN interface for tcpdump: $TCPDUMP_IFACE" >> "$OUTPUT_FILE"; fi
    fi
    if [ "$TCPDUMP_IFACE" = "any" ] || [ -z "$TCPDUMP_IFACE" ]; then
        DEFAULT_ROUTE_IFACE=$(netstat -rn -f inet|grep '^default'|awk '{print $NF}'|head -n1)
        if [ -n "$DEFAULT_ROUTE_IFACE" ]; then TCPDUMP_IFACE="$DEFAULT_ROUTE_IFACE"; echo "Using default route interface for tcpdump: $TCPDUMP_IFACE" >> "$OUTPUT_FILE";
        else echo "WARNING: Could not determine interface, attempting 'any'." >> "$OUTPUT_FILE"; TCPDUMP_IFACE="any"; fi
    fi
    echo "Capturing 100 packets of non-HTTP/HTTPS traffic on interface $TCPDUMP_IFACE..." >> "$OUTPUT_FILE"
    CMD_STR="tcpdump -i $TCPDUMP_IFACE -c 100 -vvv -n -e -X -s 0 'not (port 443 or port 80)'"
    tcpdump_label="TCPDump Non-Web Traffic on $TCPDUMP_IFACE"; execute_cmd "$CMD_STR" "$tcpdump_label" "cooldown"
    end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
    echo "Duration for $LABEL_TCPDUMP_BLOCK (incl. capture & cooldown): ${duration_block}s" >> "$OUTPUT_FILE"
    printf "Step %3d: Finished %s in %ds.\n" "$STEP_NUM" "$LABEL_TCPDUMP_BLOCK" "$duration_block" > /dev/tty
    echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

collect_opnsense_health_disk() {
    execute_if_binary_exists "$CONFIGCTL_CMD" "health fetch" "Fetch Health Data (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "firmware connection" "Firmware Connection Test (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "firmware health" "Firmware Health (configctl)"
    execute_cmd "df -h" "Disk Usage (df -h)"; execute_cmd "zpool status" "ZFS Pool Status (zpool status)"
    execute_cmd "gpart show" "Partition Layout (gpart show)"; execute_cmd "geom disk list" "Disk List (geom disk list)"
}

collect_pkg_info_integrity() {
    execute_cmd "pkg info | head -n 500" "Package Info (Top 500 lines)"
    execute_cmd "pkg check -saq" "Package Sanity Check (pkg check -saq)"
    execute_cmd "echo 'Attempting to fix pkg issues (pkg check -Ba). This may take time...';" "Message for pkg check -Ba"
    execute_cmd "pkg check -Ba" "Package Fix Attempt (pkg check -Ba)" "cooldown"
    execute_if_binary_exists "$CONFIGCTL_CMD" "firmware status" "Firmware Status (configctl)"
    execute_if_binary_exists "$OPNSENSE_UPDATE_CMD" "-s" "OPNsense Update Status (opnsense-update -s)"
}

perform_wan_gateway_tests() {
    local LABEL_GW_TEST_BLOCK start_time_block GATEWAY_DATA_RAW gateway_lines_for_loop IFS_OLD_GW line
    local gw_name iface_from_json gw_ip_from_address_field monitor_val source_ip_from_configctl current_sub_step_label
    local iface ping_target_ip ping_target_ip_no_scope
    local start_time_ping ping_cmd source_ip_to_use source_flag_arg ping_output ping_status
    local end_time_ping duration_ping packet_loss avg_rtt avg_rtt_int
    local _msg1 _msg2 _sugg1 _sugg2 _sugg3 _sugg4 _sugg5 _sugg6
    local end_time_block duration_block default_route_if

    STEP_NUM=$((STEP_NUM + 1)); LABEL_GW_TEST_BLOCK="WAN Gateway Connectivity Tests"
    printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL_GW_TEST_BLOCK" > /dev/tty; start_time_block=$(date +%s)
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL_GW_TEST_BLOCK\" (Block Start)" >> "$OUTPUT_FILE"
    echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"

    echo "Raw output of '$CONFIGCTL_CMD interface gateways status json':" >> "$OUTPUT_FILE"
    "$CONFIGCTL_CMD" interface gateways status json >> "$OUTPUT_FILE" 2>&1
    echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"

    GATEWAY_DATA_RAW=$("$CONFIGCTL_CMD" interface gateways status json 2>/dev/null)
    gateway_lines_for_loop="" 

    if command -v jq >/dev/null 2>&1 && [ -n "$GATEWAY_DATA_RAW" ] && ! echo "$GATEWAY_DATA_RAW" | grep -iq "No gateways found"; then
        # jq query: name;address;monitor;sourceip;interface
        gateway_lines_for_loop=$(echo "$GATEWAY_DATA_RAW" | \
            jq -r '.[]? | select(.address and .address != "~" and .address != null) | "\(.name // "N/A");\(.address // "N/A");\(.monitor // "N/A");\(.sourceip // "N/A");\(.interface // "N/A")"' 2>/dev/null)
        
        if [ -z "$gateway_lines_for_loop" ]; then # Fallback for "items" array
            gateway_lines_for_loop=$(echo "$GATEWAY_DATA_RAW" | \
                jq -r '.items[]? | select(.address and .address != "~" and .address != null) | "\(.name // "N/A");\(.address // "N/A");\(.monitor // "N/A");\(.sourceip // "N/A");\(.interface // "N/A")"' 2>/dev/null)
        fi
    fi
    
    if [ -z "$gateway_lines_for_loop" ]; then
      echo "No valid gateway data found to process using jq. Ensure 'jq' is installed and '$CONFIGCTL_CMD interface gateways status json' provides valid JSON array of gateways." >> "$OUTPUT_FILE"
    fi

    IFS_OLD_GW="$IFS"; IFS=$'\n'
    for line in $gateway_lines_for_loop; do
        IFS=';' read -r gw_name gw_ip_from_address_field monitor_val source_ip_from_configctl iface_from_json <<< "$line"

        iface="$iface_from_json" 
        ping_target_ip="$gw_ip_from_address_field" 

        if [ "$iface" = "N/A" ] || [ -z "$iface" ]; then
            if [[ "$monitor_val" == *%* ]]; then
                iface="${monitor_val##*%}"
            elif [[ "$gw_ip_from_address_field" == *%* ]]; then 
                iface="${gw_ip_from_address_field##*%}"
            else 
                default_route_if=$(netstat -rn -f inet | grep '^default' | awk '{print $NF}' | head -n1)
                if [ -n "$default_route_if" ]; then
                    iface="$default_route_if"
                    echo "  Note: Interface for '$gw_name' not in JSON, using default route interface '$iface'." >> "$OUTPUT_FILE"
                fi
            fi
        fi
        
        ping_target_ip_no_scope="$ping_target_ip"
        if [[ "$ping_target_ip" == *%* ]]; then
             ping_target_ip_no_scope="${ping_target_ip%%%*}" 
        fi

        if [ -z "$ping_target_ip_no_scope" ] || [ "$ping_target_ip_no_scope" = "N/A" ] || [ -z "$iface" ] || [ "$iface" = "N/A" ]; then
            echo "Skipping GW: Name='$gw_name'. Could not determine valid IP/Interface. IP(from addr): '$gw_ip_from_address_field', Iface(derived): '$iface', Monitor: '$monitor_val'" >> "$OUTPUT_FILE"
            continue
        fi

        current_sub_step_label="Pinging Gateway $gw_name ($ping_target_ip_no_scope) on $iface"
        printf "Step %3d:   %s ...\n" "$STEP_NUM" "$current_sub_step_label" > /dev/tty; start_time_ping=$(date +%s)
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        echo "Sub-COMMAND: $current_sub_step_label (Step $STEP_NUM)" >> "$OUTPUT_FILE"
        echo "  Interface: $iface"; echo "  Gateway IP to Ping: $ping_target_ip_no_scope (Original Address: $gw_ip_from_address_field)"; echo "  Source IP (configctl): $source_ip_from_configctl" >> "$OUTPUT_FILE"
        
        source_ip_to_use="$source_ip_from_configctl"
        source_flag_arg="" # Initialize to empty

        # Try to get source IP from interface if not provided by configctl
        if [ "$source_ip_to_use" = "N/A" ] || [ -z "$source_ip_to_use" ]; then
            if echo "$ping_target_ip_no_scope" | grep -q ":"; then # IPv6 target
                source_ip_to_use=$(ifconfig "$iface" inet6 | grep "inet6" | grep -v "fe80" | awk '{print $2}' | cut -d'%' -f1 | head -n1)
                if [ -z "$source_ip_to_use" ]; then # Fallback to link-local
                    source_ip_to_use=$(ifconfig "$iface" inet6 | grep "inet6 fe80" | awk '{print $2}' | cut -d'%' -f1 | head -n1)
                fi
            else # IPv4 target
                source_ip_to_use=$(ifconfig "$iface" inet | grep "inet " | awk '{print $2}' | head -n1)
            fi
        fi

        # Only add -S if source_ip_to_use is valid and not "N/A"
        if [ -n "$source_ip_to_use" ] && [ "$source_ip_to_use" != "N/A" ]; then
            source_flag_arg="-S $source_ip_to_use"
            echo "  Using Source IP for ping: $source_ip_to_use" >> "$OUTPUT_FILE"
        else
            echo "  Warn: No specific source IP determined for $iface. Ping will use system default for interface." >> "$OUTPUT_FILE"
        fi
        
        local effective_ping_ip="$ping_target_ip_no_scope" 

        if echo "$ping_target_ip_no_scope" | grep -q ":"; then # IPv6
            ping_cmd="ping6 -c 4 -W 1000" # Use -W for reply timeout
            if [[ "$gw_ip_from_address_field" == *%* ]]; then 
                effective_ping_ip="$gw_ip_from_address_field" # Use original address with scope for link-local
            fi
            ping_cmd="$ping_cmd $source_flag_arg $effective_ping_ip"
        else # IPv4
            ping_cmd="ping -c 4 -W 1000"
            ping_cmd="$ping_cmd $source_flag_arg $effective_ping_ip"
        fi

        echo "  Executing Ping Command: $ping_cmd" >> "$OUTPUT_FILE"
        ping_output=$(eval "$ping_cmd" 2>&1); ping_status=$?
        echo "$ping_output" >> "$OUTPUT_FILE"; end_time_ping=$(date +%s); duration_ping=$((end_time_ping - start_time_ping))
        echo "  Duration for this ping: ${duration_ping}s" >> "$OUTPUT_FILE"
        printf "Step %3d:     Finished pinging %s in %ds.\n" "$STEP_NUM" "$gw_name" "$duration_ping" > /dev/tty
        if [ $ping_status -eq 0 ]; then
            echo "  Status: Gateway $gw_name ($effective_ping_ip) on $iface is REACHABLE." >> "$OUTPUT_FILE"
            packet_loss=$(echo "$ping_output" | grep "packet loss" | awk '{print $7}' | sed 's/%//')
            if [ -n "$packet_loss" ]; then
                case "$packet_loss" in (*[!0-9.]*) echo "  Note: Packet loss '$packet_loss' not simple." >> "$OUTPUT_FILE" ;;
                    "") echo "  Note: Packet loss value not found." >> "$OUTPUT_FILE" ;;
                    *) if awk -v loss="$packet_loss" 'BEGIN {exit !(loss > 25)}'; then echo "  Suggest: High packet loss ($packet_loss%) detected." >> "$OUTPUT_FILE"; fi ;; esac
            fi
            avg_rtt=$(echo "$ping_output" | grep "round-trip min/avg/max/stddev" | awk -F'/' '{print $5}')
            if [ -n "$avg_rtt" ]; then
                avg_rtt_int=$(echo "$avg_rtt" | awk -F. '{print $1}')
                case "$avg_rtt_int" in (*[!0-9]*) echo "  Note: Avg RTT '$avg_rtt_int' not simple int." >> "$OUTPUT_FILE" ;;
                    "") echo "  Note: Avg RTT value not found." >> "$OUTPUT_FILE" ;;
                    *) if [ "$avg_rtt_int" -gt 200 ]; then _msg1="  Suggest: Avg RTT to gateway $gw_name ($effective_ping_ip)"; _msg2=" is high ($avg_rtt ms)."; echo "$_msg1$_msg2" >> "$OUTPUT_FILE"; fi ;; esac
            fi
        else
            echo "  Status: Gateway $gw_name ($effective_ping_ip) on $iface is UNREACHABLE (exit $ping_status)." >> "$OUTPUT_FILE"
            _sugg1="  Suggestions for UNREACHABLE gateway $gw_name ($effective_ping_ip) on $iface:"; _sugg2="\n    - Check physical connectivity, modem/ONT status."; _sugg3="\n    - Verify ISP status for outages."
            _sugg4="\n    - Review firewall rules on OPNsense."; _sugg5="\n    - Check OPNsense logs for errors on '$iface'."; _sugg6="\n    - Ensure gateway/monitor IP $effective_ping_ip is correct in OPNsense."
            echo -e "$_sugg1$_sugg2$_sugg3$_sugg4$_sugg5$_sugg6" >> "$OUTPUT_FILE"
        fi; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    done; IFS="$IFS_OLD_GW"
    end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
    echo "Duration for WAN Gateway block: ${duration_block}s" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    printf "Step %3d: Finished WAN Gateway block in %ds.\n" "$STEP_NUM" "$duration_block" > /dev/tty
    printf "Step %3d: Pausing for %d seconds after Gateway tests...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" > /dev/tty; sleep "$COOLDOWN_SECONDS"
}

collect_processes_snapshot() {
    execute_cmd "top -S -P -d1 -s1 -b -n 20" "Process Snapshot (top)"
}

collect_ntp_status() {
    execute_if_binary_exists "$CONFIGCTL_CMD" "service status ntpd" "NTPd Service Status (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "service status chronyd" "Chronyd Service Status (configctl)"
    execute_cmd "service ntpd status" "NTPd Service Status (service)"; execute_cmd "service chronyd status" "Chronyd Service Status (service)"
    if pgrep -q ntpd; then
        if command -v ntpctl >/dev/null 2>&1; then execute_cmd "ntpctl -s all" "NTP Control (ntpctl)";
        elif command -v ntpq >/dev/null 2>&1; then execute_cmd "ntpq -p" "NTP Peers (ntpq -p)";
        else STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping ntpctl/ntpq (tools missing)\n" "$STEP_NUM" >/dev/tty; echo "$DIVIDER_MINOR\nCOMMAND (File Step $STEP_NUM): \"ntpctl/ntpq\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; fi
    elif pgrep -q chronyd; then
        if command -v chronyc >/dev/null 2>&1; then execute_cmd "chronyc sources" "Chrony Sources (chronyc)";
        else STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping chronyc (tool missing)...\n" "$STEP_NUM" >/dev/tty; echo "$DIVIDER_MINOR\nCOMMAND (File Step $STEP_NUM): \"chronyc\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; fi
    else STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping NTP query (no daemon found)...\n" "$STEP_NUM" >/dev/tty; echo "$DIVIDER_MINOR\nCOMMAND (File Step $STEP_NUM): \"NTP Query\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; fi
}

collect_opnsense_services_status() {
    execute_if_binary_exists "$CONFIGCTL_CMD" "service list" "List All Services (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "service status" "Status All Services (configctl)"
}

collect_key_config_files() {
    cat_if_exists "/etc/rc.conf"; cat_if_exists "/etc/rc.conf.local"; cat_if_exists "/etc/hosts"; cat_if_exists "/etc/fstab"
    cat_if_exists "/usr/local/etc/syslog-ng/syslog-ng.conf"; cat_if_exists "/etc/syslog.conf"; cat_if_exists "/var/etc/ntp.conf"
    cat_if_exists "/usr/local/etc/chrony.conf"; cat_if_exists "/etc/dhclient.conf"; cat_if_exists "/etc/crontab"
    cat_if_exists "/var/cron/tabs/root"; cat_if_exists "/etc/newsyslog.conf"; cat_if_exists "/etc/shells"; cat_if_exists "/etc/motd"
}

collect_kernel_env() {
    local LABEL_SYSCTL start_time_block end_time_block duration_block
    STEP_NUM=$((STEP_NUM + 1)); LABEL_SYSCTL="Kernel Environment (sysctl -a)"
    printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL_SYSCTL" > /dev/tty; start_time_block=$(date +%s)
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL_SYSCTL\" (NOTE: This output is very large)" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    sysctl -a >> "$OUTPUT_FILE" 2>&1; end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
    echo "Duration for $LABEL_SYSCTL: ${duration_block}s" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    printf "Step %3d: Finished %s in %ds.\n" "$STEP_NUM" "$LABEL_SYSCTL" "$duration_block" > /dev/tty
    printf "Step %3d: Pausing for %d seconds after %s...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" "$LABEL_SYSCTL" > /dev/tty; sleep "$COOLDOWN_SECONDS"
}

declare -a SECTION_FUNCTIONS SECTION_DESCRIPTIVE_NAMES
SECTION_FUNCTIONS=( "collect_system_info" "collect_hardware_diagnostics" "collect_interface_config" "collect_routing_arp" "collect_arp_timeouts" "collect_dns_resolution" "collect_firewall_pf_diagnostics" "collect_net_connections" "collect_system_logs" "perform_connectivity_tests_general" "capture_tcpdump_non_web" "collect_opnsense_health_disk" "collect_pkg_info_integrity" "perform_wan_gateway_tests" "collect_processes_snapshot" "collect_ntp_status" "collect_opnsense_services_status" "collect_key_config_files" "collect_kernel_env" )
SECTION_DESCRIPTIVE_NAMES=( "System Information" "Hardware Diagnostics" "Interface Configuration & Status" "Routing Table & ARP" "ARP Timeout Configuration" "DNS Configuration & Resolution" "Firewall (PF) Diagnostics" "Network Connections & Services" "System Logs" "Connectivity Tests (General)" "TCPDump Non-Web Traffic" "OPNsense Health & Disk Space" "Package Information & Integrity" "WAN Gateway Connectivity & Health" "Running Processes Snapshot" "NTP/Time Service Status" "OPNsense Services Status" "Key Configuration Files" "Kernel Environment (sysctl)" )

initialize_output_file; perform_initial_checks
echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "INDEX OF DIAGNOSTIC SECTIONS:" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
for i in "${!SECTION_FUNCTIONS[@]}"; do current_section_num=$((i + 1)); echo "Section $current_section_num: ${SECTION_DESCRIPTIVE_NAMES[i]}" >> "$OUTPUT_FILE"; done
echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
for i in "${!SECTION_FUNCTIONS[@]}"; do
    SECTION_NUM=$((i + 1)); section_func_name="${SECTION_FUNCTIONS[i]}"; section_desc_name="${SECTION_DESCRIPTIVE_NAMES[i]}"
    section_start_time=$(date +%s); echo "" > /dev/tty 
    printf "Starting Section %d: %s\n" "$SECTION_NUM" "$section_desc_name" > /dev/tty
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; printf "SECTION %d: %s\n" "$SECTION_NUM" "$section_desc_name" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    "$section_func_name" # Call the actual collection function
    section_end_time=$(date +%s); section_duration=$((section_end_time - section_start_time))
    printf "Finished Section %d: %s in %ds.\n" "$SECTION_NUM" "$section_desc_name" "$section_duration" > /dev/tty
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "Section $SECTION_NUM '$section_desc_name' completed in ${section_duration}s." >> "$OUTPUT_FILE"
done
echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; echo "Diagnostics collection finished." >> "$OUTPUT_FILE"; echo "Output file: $OUTPUT_FILE" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
MD5_FILE="${OUTPUT_FILE}.md5"; SHA256_FILE="${OUTPUT_FILE}.sha256"
MD5_HASH=$( (md5 -q "$OUTPUT_FILE" 2>/dev/null || md5sum "$OUTPUT_FILE" 2>/dev/null | awk '{print $1}') || echo "md5_tool_not_found_or_failed")
SHA256_HASH=$( (sha256 -q "$OUTPUT_FILE" 2>/dev/null || sha256sum "$OUTPUT_FILE" 2>/dev/null | awk '{print $1}') || echo "sha256_tool_not_found_or_failed")
echo "$MD5_HASH" > "$MD5_FILE"; echo "$SHA256_HASH" > "$SHA256_FILE"
sync; echo "" > /dev/tty; echo "Diagnostics collection finished. Output saved to $OUTPUT_FILE" > /dev/tty
echo "MD5: $MD5_HASH (saved to $MD5_FILE)" > /dev/tty; echo "SHA256: $SHA256_HASH (saved to $SHA256_FILE)" > /dev/tty
exit 0
