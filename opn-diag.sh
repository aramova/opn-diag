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
# - Changed MAC address sanitization to keep the OUI (v0.50.8)
# - Added static sanitize status banner to TTY output (v0.50.9)
# - Fixed sed sanitization for BSD compatibility (v0.50.10)
# - Moved sanitized status to bottom right of TTY (v0.50.11)
# - Added descriptive IP sanitization (v0.50.12)
# - Improved TTY output to be cleaner and more stable (v0.50.14)
# - Reverted sanitize banner to top right of TTY (v0.50.15)
# - Improved TTY output by reducing newlines and banner refreshes (v0.50.13)
# - Fixed unrecognized argument for configctl filter list states (v0.50.17)
# - Added -n flag to mtr to disable dns resolution for hops (v0.50.18)
# - Skip tcpdump when in sanitize mode (v0.50.19)
# - Redact serial numbers from geom disk list in sanitize mode (v0.50.20)
# - Improved FQDN sanitization (v0.50.21)
# - Refined FQDN regex to be more specific (v0.50.22)
# - Updated FQDN redaction to use a list of official TLDs (v0.50.23)
# - Prevented incorrect sanitization of kernel tunables (v0.50.24)
# - Added detailed comments to all functions (v0.50.25)

SCRIPT_VERSION="v0.50.25"
OUTPUT_FILE="opnsense_diagnostics_output_$(date +%Y%m%d_%H%M%S).txt"
DIVIDER_MAJOR="================================================================================"
DIVIDER_MINOR="--------------------------------------------------------------------------------"
COOLDOWN_SECONDS=1 # Seconds to pause after certain long-running commands

SANITIZE_MODE=false
if [ "$1" = "--sanitize" ]; then
    SANITIZE_MODE=true
fi

# TTY Status Banner Colors & Text
if [ -t 1 ]; then # Ensure we are in an interactive terminal
    C_GREEN=$(tput setaf 2)
    C_RED=$(tput setaf 1)
    C_RESET=$(tput sgr0)
fi
MSG_SANITIZED="${C_GREEN}SANITIZED OUTPUT${C_RESET}"
MSG_UNSANITIZED="${C_RED}UNSANITIZED OUTPUT${C_RESET}"


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

#
# Displays a colored banner at the top right of the terminal indicating
# whether the script output is being sanitized. This provides a constant,
# clear visual cue to the user about the state of the final output file.
#
# Expects:
#   - The global variable SANITIZE_MODE to be 'true' or 'false'.
#   - Terminal colors (C_GREEN, C_RED, C_RESET) to be set if the TTY is interactive.
#
# Usage:
#   display_status_banner
#
display_status_banner() {
    if [ ! -t 1 ]; then return; fi # Skip if not interactive TTY
    local message
    local message_len
    local term_width
    local col
    
    if [ "$SANITIZE_MODE" = true ]; then
        message="$MSG_SANITIZED"
        message_len=18 # Length of "SANITIZED OUTPUT" + color codes
    else
        message="$MSG_UNSANITIZED"
        message_len=20 # Length of "UNSANITIZED OUTPUT" + color codes
    fi

    term_width=$(tput cols)
    col=$((term_width - message_len - 2)) # 2 for padding

    tput sc # Save cursor position
    tput cup 0 "$col" # Move to top right
    echo -e "$message"
    tput rc # Restore cursor position
}


#
# Creates and initializes the main output file. It adds a header with the
# script version, collection date, hostname, and OPNsense version.
#
# Expects:
#   - The global variables SCRIPT_VERSION and OUTPUT_FILE to be set.
#   - The command defined in OPNSENSE_VERSION_CMD to be executable.
#
# Usage:
#   initialize_output_file
#
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

#
# Performs initial checks before starting the main diagnostic collection.
# It clears the screen, displays the status banner, and checks for the
# existence and permissions of all required and optional diagnostic tools.
# The results of these checks are printed to both the TTY and the output file.
#
# Expects:
#   - The global arrays CMD_PATHS_TO_CHECK and related command path
#     variables to be defined.
#
# Usage:
#   perform_initial_checks
#
perform_initial_checks() {
    clear # Clear screen for clean banner display
    display_status_banner
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

#
# A centralized wrapper function for executing most shell commands.
# It handles all the logic for logging, timing, and status reporting for
# each step. It prints a clean, single-line status to the TTY and logs
# the verbose command, output, duration, and exit status to the output file.
#
# Parameters:
#   $1: CMD_STRING - The full command to be executed, as a single string.
#   $2: LABEL - A human-readable description of what the command does.
#   $3: APPLY_COOLDOWN - (Optional) If set to the string "cooldown", the
#       function will pause for COOLDOWN_SECONDS after the command completes.
#
# Usage:
#   execute_cmd "cat /etc/resolv.conf" "Show DNS Resolver Config"
#   execute_cmd "pfctl -s info" "Get PF Info" "cooldown"
#
execute_cmd() {
  local CMD_STRING=$1 LABEL=$2 APPLY_COOLDOWN=$3
  local cmd_status start_time end_time duration
  STEP_NUM=$((STEP_NUM + 1))
  printf "Step %3d: Running: %-50s" "$STEP_NUM" "$LABEL" > /dev/tty
  start_time=$(date +%s)
  echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
  # Quote LABEL for file output to preserve spaces
  echo "COMMAND (File Step $STEP_NUM): \"$LABEL\"" >> "$OUTPUT_FILE"
  echo "Actual command: $CMD_STRING" >> "$OUTPUT_FILE"
  echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
  eval "$CMD_STRING" >> "$OUTPUT_FILE" 2>&1; cmd_status=$?
  end_time=$(date +%s); duration=$((end_time - start_time))
  echo "Duration: ${duration}s. Exit status: $cmd_status" >> "$OUTPUT_FILE"
  printf "\rStep %3d: Finished: %-50s (%ds, Status: %d)\n" "$STEP_NUM" "$LABEL" "$duration" "$cmd_status" > /dev/tty
  if [ "$APPLY_COOLDOWN" = "cooldown" ]; then
      printf "Step %3d: Pausing for %d seconds after %s...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" "$LABEL" > /dev/tty
      sleep "$COOLDOWN_SECONDS"
  fi
  display_status_banner
  echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

#
# A wrapper around execute_cmd that first checks if a specific binary
# exists and is executable. If it is, the command is run. If not, the
# step is skipped with a message, and a suggestion for how to install
# the missing tool is often provided.
#
# Parameters:
#   $1: CMD_PATH - The absolute path to the binary to check.
#   $2: CMD_ARGS - A string of arguments to pass to the command.
#   $3: LABEL - A human-readable description of the step.
#   $4: APPLY_COOLDOWN - (Optional) Passed through to execute_cmd.
#
# Usage:
#   execute_if_binary_exists "/usr/local/bin/lscpu" "" "Get CPU Info"
#
execute_if_binary_exists() {
  local CMD_PATH=$1 CMD_ARGS=$2 LABEL=$3 APPLY_COOLDOWN=$4
  local suggestion cmd_status start_time end_time duration full_command=()
  STEP_NUM=$((STEP_NUM + 1))
  if [ -x "$CMD_PATH" ]; then
    printf "Step %3d: Running: %-50s" "$STEP_NUM" "$LABEL" > /dev/tty
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
    printf "\rStep %3d: Finished: %-50s (%ds, Status: %d)\n" "$STEP_NUM" "$LABEL" "$duration" "$cmd_status" > /dev/tty
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
    printf "Step %3d: Skipping: %s (binary %s not found %s)%s\n" "$STEP_NUM" "$LABEL" "$CMD_PATH" "or not executable" "$suggestion" > /dev/tty
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    # Quote LABEL for file output
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL\" (SKIPPED - $CMD_PATH not found or not executable)$suggestion" >> "$OUTPUT_FILE"
    echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
  fi
  display_status_banner
  echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

#
# A wrapper function that safely cats a file to the output log.
# It checks if the file exists and is readable before attempting to cat it.
# If the file is not accessible, it logs a skipped message.
#
# Parameters:
#   $1: FILE_PATH - The absolute path to the file to be read.
#
# Usage:
#   cat_if_exists "/etc/resolv.conf"
#
cat_if_exists() {
    local FILE_PATH=$1
    local LABEL="Content of $FILE_PATH" 
    if [ -f "$FILE_PATH" ] && [ -r "$FILE_PATH" ]; then
        execute_cmd "cat \"$FILE_PATH\"" "$LABEL" 
    else
        STEP_NUM=$((STEP_NUM + 1))
        printf "Step %3d: Skipping: %s (File not found: %s)\n" "$STEP_NUM" "$LABEL" "$FILE_PATH" > /dev/tty
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        # Use direct string construction for the label in the skipped message
        echo "COMMAND (File Step $STEP_NUM): Content of $FILE_PATH (SKIPPED - File not found or not readable: $FILE_PATH)" >> "$OUTPUT_FILE"
        echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
}

#
# Collects fundamental system and operating system information.
# This section establishes a baseline of the OPNsense version, FreeBSD kernel,
# uptime, and hardware sensor status.
#
# Gathers:
#   - OS and kernel version (`uname`, `freebsd-version`)
#   - System uptime and load
#   - Kernel boot messages (`dmesg.boot`)
#   - OPNsense system status and hardware sensor data (`configctl`)
#
collect_system_info() {
    execute_cmd "uname -a" "Get System Name (uname -a)"
    execute_cmd "freebsd-version -ukr" "Get FreeBSD Version"
    execute_cmd "uptime" "Get System Uptime"
    cat_if_exists "/var/run/dmesg.boot"
    execute_if_binary_exists "$CONFIGCTL_CMD" "system status" "Get OPNsense System Status (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "system sensors" "Get System Sensors (configctl)"
}

#
# Gathers detailed information about the physical hardware components of the system.
# This is crucial for diagnosing issues related to CPU, storage, and the motherboard.
#
# Gathers:
#   - CPU details (`lscpu`)
#   - Block device listing (`lsblk`)
#   - General hardware status (`hwstat`)
#   - System/BIOS manufacturer and version details (`dmidecode`)
#   - Disk partition and geometry information (`geom`)
#   - Detailed disk health status for all physical disks (`smartctl`)
#
# Note:
#   - When in sanitize mode, this function redacts disk serial numbers.
#
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
    if [ "$SANITIZE_MODE" = true ]; then
        execute_cmd "geom disk list | sed -E 's/serial: .*/serial: [REDACTED]/g'" "List Disks (geom disk list, sanitized)"
    else
        execute_cmd "geom disk list" "List Disks (geom disk list)"
    fi
    STEP_NUM=$((STEP_NUM + 1)); LABEL_SMART="SMARTCTL Diagnostics for Disks"
    printf "Step %3d: Running: %-50s" "$STEP_NUM" "$LABEL_SMART" > /dev/tty
    start_time_block=$(date +%s)
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL_SMART\" (Block Start)" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    if [ -x "$SMARTCTL_CMD" ]; then
        DISKS=$(sysctl -n kern.disks | tr ' ' '\n' | grep -E '^(ada|da|nvme[0-9]+ns[0-9]+|mmcsd[0-9]+|vtbd[0-9]+)')
        if [ -n "$DISKS" ]; then
            for disk in $DISKS; do
                printf "\rStep %3d:   Getting SMART info for /dev/%-15s" "$STEP_NUM" "$disk" > /dev/tty
                echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "SMART Information for /dev/$disk:" >> "$OUTPUT_FILE"
                "$SMARTCTL_CMD" -a "/dev/$disk" >> "$OUTPUT_FILE" 2>&1
                echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"; echo "SMART Health Status for /dev/$disk:" >> "$OUTPUT_FILE"
                "$SMARTCTL_CMD" -H "/dev/$disk" >> "$OUTPUT_FILE" 2>&1; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
            done
        else echo "No suitable disk devices for SMART diagnostics." >> "$OUTPUT_FILE"; fi
    else echo "SKIPPED - $SMARTCTL_CMD not found or not exec." >> "$OUTPUT_FILE"; fi
    end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
    echo "Duration for $LABEL_SMART: ${duration_block}s" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    printf "\rStep %3d: Finished: %-50s (%ds)\n" "$STEP_NUM" "$LABEL_SMART" "$duration_block" > /dev/tty
    printf "Step %3d: Pausing for %d seconds after %s...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" "$LABEL_SMART" > /dev/tty
    display_status_banner
    sleep "$COOLDOWN_SECONDS"
}

#
# Collects a comprehensive snapshot of the network interface configuration,
# status, and statistics. This is one of the most critical sections for
# diagnosing all types of network connectivity issues.
#
# Gathers:
#   - Verbose interface details including MAC, IP, MTU, and flags (`ifconfig`)
#   - OPNsense's view of interface configuration and stats (`configctl`)
#   - Packet, error, and drop counts for all interfaces (`netstat`)
#   - Recent kernel messages, which may show link state changes (`dmesg`)
#   - CARP (HA) status (`configctl`)
#
collect_interface_config() {
    execute_cmd "ifconfig -a -vv" "Full Interface Details (ifconfig -a -vv)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list ifconfig" "Interface List (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface show interfaces" "Interface Summary (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list stats" "Interface Stats (configctl)"
    execute_cmd "netstat -i -n -d -h -W" "Network Interface Statistics (netstat -indhW)"
    execute_cmd "dmesg -a | tail -n 500" "Recent Kernel Messages (dmesg)" "cooldown"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface show carp" "CARP Status (configctl)"
}

#
# Gathers information about the Layer 3 networking environment, including
# routing tables, ARP/NDP tables, and gateway status. This section helps
# diagnose issues with traffic flow and local network address resolution.
#
# Gathers:
#   - Kernel routing tables (`netstat -r`)
#   - OPNsense's view of configured routes (`configctl`)
#   - ARP (IPv4) and NDP (IPv6) tables (`arp`, `configctl`)
#   - Real-time status of configured gateways (`configctl`)
#
collect_routing_arp() {
    execute_cmd "netstat -r -n -A -W" "Routing Tables (netstat -rnAW)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface routes list" "Routes List (configctl)"
    execute_cmd "netstat -rs" "Routing Statistics (netstat -rs)"
    execute_cmd "arp -a -n" "ARP Table (arp -an)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list arp" "ARP List (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface list ndp" "NDP List (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface gateways status" "Gateway Status (configctl)"
}

#
# Retrieves kernel-level configuration values related to ARP timeouts.
# This is useful for advanced troubleshooting of intermittent connectivity
# issues where devices might be dropping off the network due to stale
# or expiring ARP entries.
#
# Gathers:
#   - ARP timeout and retry settings from `sysctl`.
#
collect_arp_timeouts() {
    execute_cmd "sysctl net.link.ether.inet" "ARP System Configuration (sysctl net.link.ether.inet)"
}

#
# This section performs a deep dive into the DNS configuration and resolution
# capabilities of the firewall. DNS is a frequent source of network problems,
# and this function checks it from multiple angles.
#
# Gathers:
#   - The firewall's own resolver configuration (`/etc/resolv.conf`).
#   - DNS servers configured in OPNsense (`configctl`).
#   - Status of local DNS services (Unbound, Dnsmasq).
#   - Detailed statistics from Unbound DNS resolver.
#   - Live tests of external and internal DNS resolution using `drill`.
#
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
        echo "$DIVIDER_([a-zA-Z0-9-]+\.)+(aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shell|shia|shiksha|shoes|shop|shopping|shouji|show|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw) (File Step $STEP_NUM): \"unbound-control\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
      fi
      execute_if_binary_exists "$CONFIGCTL_CMD" "unbound stats" "Unbound Stats (configctl)"
    else
        STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping Unbound stats (not running)...\n" "$STEP_NUM" > /dev/tty
        echo "$DIVIDER_([a-zA-Z0-9-]+\.)+(aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shell|shia|shiksha|shoes|shop|shopping|shouji|show|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw) (File Step $STEP_NUM): \"Unbound specific stats\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
    execute_if_binary_exists "$DRILL_CMD" "-V 4 google.com" "Drill google.com"
    execute_if_binary_exists "$DRILL_CMD" "-V 4 $(hostname)" "Drill Local Hostname"
    if [ -x "$CONFIGCTL_CMD" ] && [ -x "$DRILL_CMD" ]; then
        STEP_NUM=$((STEP_NUM + 1)); LABEL_LOCAL_ZONES="Testing Local Unbound Zones with drill"
        printf "Step %3d: Running: %-50s" "$STEP_NUM" "$LABEL_LOCAL_ZONES" > /dev/tty; start_time_block=$(date +%s)
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        echo "COMMAND (File Step $STEP_NUM): \"$LABEL_LOCAL_ZONES\" (via configctl unbound listlocalzones)" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        LOCAL_ZONES_OUTPUT=$($CONFIGCTL_CMD unbound listlocalzones 2>/dev/null)
        if [ -n "$LOCAL_ZONES_OUTPUT" ]; then
            echo "Local zones reported:" >> "$OUTPUT_FILE"; echo "$LOCAL_ZONES_OUTPUT" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
            IFS_OLD_DRILL="$IFS"; IFS=$'\n'
            for zone_line in $LOCAL_ZONES_OUTPUT; do
                zone_to_test=$(echo "$zone_line"|awk '{print $1}'|sed 's/\.$//')
                if [ -n "$zone_to_test" ]; then
                    printf "\rStep %3d:   Drilling local zone: %-30s" "$STEP_NUM" "$zone_to_test" > /dev/tty
                    echo "Drilling local zone: $zone_to_test" >> "$OUTPUT_FILE"
                    "$DRILL_CMD" -V 4 "$zone_to_test" >> "$OUTPUT_FILE" 2>&1; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
                fi
            done; IFS="$IFS_OLD_DRILL"
        else echo "No local zones by 'configctl unbound listlocalzones'." >> "$OUTPUT_FILE"; fi
        end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
        echo "Duration for Local Zone Drill block: ${duration_block}s" >> "$OUTPUT_FILE"
        printf "\rStep %3d: Finished: %-50s (%ds)\n" "$STEP_NUM" "$LABEL_LOCAL_ZONES" "$duration_block" > /dev/tty
        echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    else
        STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping dynamic local zone drill...\n" "$STEP_NUM" > /dev/tty
        echo "$DIVIDER_([a-zA-Z0-9-]+\.)+(aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shell|shia|shiksha|shoes|shop|shopping|shouji|show|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw) (File Step $STEP_NUM): \"Dynamic Local Zone Drill\" (SKIPPED)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    fi
    display_status_banner
}

#
# Gathers diagnostic information from the Packet Filter (PF) firewall,
# which is the core of OPNsense's filtering capabilities. This section
# is essential for debugging any issue related to firewall rules, NAT,
# or traffic shaping.
#
# Gathers:
#   - Active firewall rules (`pfctl -s rules`)
#   - NAT rules (`pfctl -s nat`)
#   - A sample of the firewall state table (`pfctl -s states`)
#   - General PF status and statistics (`pfctl -s info`)
#   - The contents of all PF tables (`pfctl -s Tables`)
#
collect_firewall_pf_diagnostics() {
    execute_cmd "pfctl -s rules -vv" "PF Rules (pfctl -s rules -vv)"
    execute_cmd "pfctl -s nat -vv" "PF NAT Rules (pfctl -s nat -vv)"
    execute_cmd "echo 'Firewall States (first 500 lines):'; pfctl -s states -vv | head -n 500" "PF States (Top 500)" "cooldown"
    execute_if_binary_exists "$CONFIGCTL_CMD" "filter list states" "PF States (configctl, Top 500)"
    execute_cmd "pfctl -s info -vv" "PF Info (pfctl -s info -vv)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "filter diag info" "PF Info (configctl)"
    execute_cmd "pfctl -s Tables -vv" "PF Tables (pfctl -s Tables -vv)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "filter list tables" "PF Tables (configctl)"
}

#
# Collects information about current network connections and socket
# statistics. This is useful for understanding what services are listening
# for connections and for diagnosing resource exhaustion issues related to
# networking.
#
# Gathers:
#   - All listening and established network sockets (`netstat -an`)
#   - Detailed statistics for each network protocol (`netstat -ss`)
#   - A summary of open sockets by process (`sockstat`)
#   - Kernel memory usage for network buffers (mbufs) (`netstat -m`)
#   - Interrupt statistics (`vmstat -i`)
#
collect_net_connections() {
    execute_cmd "netstat -an -A" "All Network Sockets (netstat -anA)"
    execute_cmd "netstat -ss" "Network Statistics by Protocol (netstat -ss)"
    execute_cmd "sockstat -4 -6 -c -l -u" "Socket Status (sockstat)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface dump sockstat" "Socket Dump (configctl)"
    execute_cmd "netstat -m" "Mbuf Usage (netstat -m)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "system show mbuf" "Mbuf Usage (configctl)"
    execute_cmd "vmstat -i" "Interrupt Statistics (vmstat -i)"
}

#
# Gathers recent log entries from various OPNsense-specific log files.
# This provides critical context for almost any issue, as errors and
# important events are typically logged.
#
# Gathers:
#   - The last 200 lines of the main system log.
#   - The last 200 lines of the firewall (filter) log.
#   - The last 100 lines of the routing, resolver (DNS), DHCP,
#     and NTP daemon logs.
#
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

#
# Performs basic, general-purpose internet connectivity tests from the
# firewall itself. This helps to quickly determine if the firewall has
# a fundamental issue with reaching the internet.
#
# Gathers:
#   - Ping tests to common public DNS servers (8.8.8.8, 1.1.1.1).
#   - A traceroute to 8.8.8.8 to check the path to the internet.
#   - An MTR (My Traceroute) report, which combines ping and traceroute
#     to diagnose path quality and packet loss.
#
perform_connectivity_tests_general() {
    execute_cmd "ping -c 5 8.8.8.8" "Ping 8.8.8.8"; execute_cmd "ping -c 5 1.1.1.1" "Ping 1.1.1.1"
    execute_cmd "traceroute -n -w 1 8.8.8.8" "Traceroute to 8.8.8.8"
    execute_if_binary_exists "$CONFIGCTL_CMD" "interface traceroute 8.8.8.8" "Traceroute via configctl"
    execute_if_binary_exists "$MTR_CMD" "-n -rwc 5 8.8.8.8" "MTR to 8.8.8.8"
}

#
# Captures a small sample of live network traffic. This is an advanced
# diagnostic step that is useful for debugging complex protocol-level
# issues.
#
# Gathers:
#   - A capture of 100 packets on the primary WAN interface.
#   - The capture is configured to be highly verbose (`-vvv -e -X`) and
#     to exclude common web traffic (ports 80 and 443) to focus on
#     other potentially problematic traffic.
#
# Note:
#   - This entire section is skipped if the --sanitize flag is used, as
#     packet captures are very likely to contain sensitive data.
#
capture_tcpdump_non_web() {
    if [ "$SANITIZE_MODE" = true ]; then
        STEP_NUM=$((STEP_NUM + 1))
        printf "Step %3d: Skipping: TCPDump Non-Web Traffic Capture (Sanitize Mode)\n" "$STEP_NUM" > /dev/tty
        echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        echo "COMMAND (File Step $STEP_NUM): \"TCPDump Non-Web Traffic Capture\" (SKIPPED due to --sanitize flag)" >> "$OUTPUT_FILE"
        echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
        echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
        display_status_banner
        return
    fi
    local LABEL_TCPDUMP_BLOCK start_time_block TCPDUMP_IFACE WAN_IFACE_DETAILS
    local DEFAULT_ROUTE_IFACE CMD_STR end_time_block duration_block tcpdump_label
    STEP_NUM=$((STEP_NUM + 1)); LABEL_TCPDUMP_BLOCK="TCPDump Non-Web Traffic Capture Block"
    printf "Step %3d: Running: %-50s" "$STEP_NUM" "$LABEL_TCPDUMP_BLOCK" > /dev/tty; start_time_block=$(date +%s)
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
    printf "\rStep %3d: Finished: %-50s (%ds)\n" "$STEP_NUM" "$LABEL_TCPDUMP_BLOCK" "$duration_block" > /dev/tty
    display_status_banner
    echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
}

#
# Checks the overall health of the OPNsense system, including firmware
# status and disk space usage. This is a good starting point for checking
# the general well-being of the firewall.
#
# Gathers:
#   - OPNsense health and firmware connection/status (`configctl`)
#   - Filesystem disk usage (`df -h`)
#   - ZFS pool status, if applicable (`zpool status`)
#   - Disk partition layout (`gpart show`)
#
collect_opnsense_health_disk() {
    execute_if_binary_exists "$CONFIGCTL_CMD" "health fetch" "Fetch Health Data (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "firmware connection" "Firmware Connection Test (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "firmware health" "Firmware Health (configctl)"
    execute_cmd "df -h" "Disk Usage (df -h)"; execute_cmd "zpool status" "ZFS Pool Status (zpool status)"
    execute_cmd "gpart show" "Partition Layout (gpart show)"; execute_cmd "geom disk list" "Disk List (geom disk list)"
}

#
# Gathers information about installed software packages and checks their
# integrity. This is crucial for ensuring that the system's software
# is in a consistent and healthy state.
#
# Gathers:
#   - A list of all installed packages (`pkg info`)
#   - A sanity check of package dependencies (`pkg check -saq`)
#   - An attempt to automatically fix any package issues (`pkg check -Ba`)
#   - The firmware status as reported by OPNsense (`configctl`)
#
collect_pkg_info_integrity() {
    execute_cmd "pkg info | head -n 500" "Package Info (Top 500 lines)"
    execute_cmd "pkg check -saq" "Package Sanity Check (pkg check -saq)"
    execute_cmd "echo 'Attempting to fix pkg issues (pkg check -Ba). This may take time...';" "Message for pkg check -Ba"
    execute_cmd "pkg check -Ba" "Package Fix Attempt (pkg check -Ba)" "cooldown"
    execute_if_binary_exists "$CONFIGCTL_CMD" "firmware status" "Firmware Status (configctl)"
    execute_if_binary_exists "$OPNSENSE_UPDATE_CMD" "-s" "OPNsense Update Status (opnsense-update -s)"
}

#
# Performs detailed, dynamic connectivity tests for each configured WAN
# gateway. This is the most important section for diagnosing multi-WAN
# failover, load balancing, and specific gateway connectivity problems.
#
# Logic:
#   1. It gets a structured JSON list of all gateways from `configctl`.
#   2. It iterates through each gateway.
#   3. For each gateway, it intelligently determines the correct source IP
#      and target IP to use for testing.
#   4. It executes a ping test and analyzes the output for reachability,
#      packet loss, and latency, providing suggestions based on the results.
#
# Gathers:
#   - Raw JSON output of gateway status.
#   - Individual ping tests for each gateway.
#   - Analysis of packet loss and round-trip time (RTT).
#
perform_wan_gateway_tests() {
    local LABEL_GW_TEST_BLOCK start_time_block GATEWAY_DATA_RAW gateway_lines_for_loop IFS_OLD_GW line
    local gw_name iface_from_json gw_ip_from_address_field monitor_val source_ip_from_configctl current_sub_step_label
    local iface ping_target_ip ping_target_ip_no_scope
    local start_time_ping ping_cmd source_ip_to_use source_flag_arg ping_output ping_status
    local end_time_ping duration_ping packet_loss avg_rtt avg_rtt_int
    local _msg1 _msg2 _sugg1 _sugg2 _sugg3 _sugg4 _sugg5 _sugg6
    local end_time_block duration_block default_route_if

    STEP_NUM=$((STEP_NUM + 1)); LABEL_GW_TEST_BLOCK="WAN Gateway Connectivity Tests"
    printf "Step %3d: Running: %s ...\n" "$STEP_NUM" "$LABEL_GW_TEST_BLOCK" > /dev/tty; display_status_banner; start_time_block=$(date +%s)
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
        printf "\rStep %3d:   %-60s" "$STEP_NUM" "$current_sub_step_label" > /dev/tty; start_time_ping=$(date +%s)
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
    printf "\rStep %3d: Finished: %-50s (%ds)\n" "$STEP_NUM" "$LABEL_GW_TEST_BLOCK" "$duration_block" > /dev/tty
    printf "Step %3d: Pausing for %d seconds after Gateway tests...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" > /dev/tty; display_status_banner; sleep "$COOLDOWN_SECONDS"
}

#
# Captures a snapshot of the currently running processes on the system.
# This is useful for identifying processes that are consuming high CPU or
# memory, or for checking if expected services are running.
#
# Gathers:
#   - A snapshot from the `top` command, sorted by CPU usage.
#
collect_processes_snapshot() {
    execute_cmd "top -S -P -d1 -s1 -b -n 20" "Process Snapshot (top)"
}

#
# Checks the status of the Network Time Protocol (NTP) service, which is
# critical for time synchronization. Correct time is essential for logging,
# authentication (like Kerberos or 2FA), and certificate validation.
#
# Gathers:
#   - The status of the ntpd and chronyd services (`configctl`, `service`)
#   - A list of NTP peers and their status (`ntpctl` or `ntpq`)
#   - A list of Chrony time sources (`chronyc`)
#
collect_ntp_status() {
    execute_if_binary_exists "$CONFIGCTL_CMD" "service status ntpd" "NTPd Service Status (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "service status chronyd" "Chronyd Service Status (configctl)"
    execute_cmd "service ntpd status" "NTPd Service Status (service)"; execute_cmd "service chronyd status" "Chronyd Service Status (service)"
    if pgrep -q ntpd; then
        if command -v ntpctl >/dev/null 2>&1; then execute_cmd "ntpctl -s all" "NTP Control (ntpctl)";
        elif command -v ntpq >/dev/null 2>&1; then execute_cmd "ntpq -p" "NTP Peers (ntpq -p)";
        else STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping: ntpctl/ntpq (tools missing)\n" "$STEP_NUM" >/dev/tty; echo "$DIVIDER_([a-zA-Z0-9-]+\.)+(aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shell|shia|shiksha|shoes|shop|shopping|shouji|show|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw) (File Step $STEP_NUM): \"ntpctl/ntpq\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; fi
    elif pgrep -q chronyd; then
        if command -v chronyc >/dev/null 2>&1; then execute_cmd "chronyc sources" "Chrony Sources (chronyc)";
        else STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping: chronyc (tool missing)...\n" "$STEP_NUM" >/dev/tty; echo "$DIVIDER_([a-zA-Z0-9-]+\.)+(aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shell|shia|shiksha|shoes|shop|shopping|shouji|show|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw) (File Step $STEP_NUM): \"chronyc\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; fi
    else STEP_NUM=$((STEP_NUM+1)); printf "Step %3d: Skipping: NTP query (no daemon found)...\n" "$STEP_NUM" >/dev/tty; echo "$DIVIDER_([a-zA-Z0-9-]+\.)+(aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shell|shia|shiksha|shoes|shop|shopping|shouji|show|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw) (File Step $STEP_NUM): \"NTP Query\" (skipped)\n$DIVIDER_MINOR\n$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; fi
    display_status_banner
}

#
# Gathers the status of all services managed by the OPNsense framework.
# This provides a high-level overview of which services are enabled and
# whether they are currently running.
#
# Gathers:
#   - A list of all available services from `configctl`.
#   - The running status of all services from `configctl`.
#
collect_opnsense_services_status() {
    execute_if_binary_exists "$CONFIGCTL_CMD" "service list" "List All Services (configctl)"
    execute_if_binary_exists "$CONFIGCTL_CMD" "service status" "Status All Services (configctl)"
}

#
# Dumps the content of several key system configuration files. This is
# useful for advanced troubleshooting where a manual configuration change
# or corruption might be suspected.
#
# Gathers:
#   - Core system config (`rc.conf`, `hosts`, `fstab`)
#   - Syslog configuration (`syslog-ng.conf`, `syslog.conf`)
#   - NTP/Chrony configuration (`ntp.conf`, `chrony.conf`)
#   - Cron jobs (`crontab`, `root`)
#
collect_key_config_files() {
    cat_if_exists "/etc/rc.conf"; cat_if_exists "/etc/rc.conf.local"; cat_if_exists "/etc/hosts"; cat_if_exists "/etc/fstab"
    cat_if_exists "/usr/local/etc/syslog-ng/syslog-ng.conf"; cat_if_exists "/etc/syslog.conf"; cat_if_exists "/var/etc/ntp.conf"
    cat_if_exists "/usr/local/etc/chrony.conf"; cat_if_exists "/etc/dhclient.conf"; cat_if_exists "/etc/crontab"
    cat_if_exists "/var/cron/tabs/root"; cat_if_exists "/etc/newsyslog.conf"; cat_if_exists "/etc/shells"; cat_if_exists "/etc/motd"
}

#
# Dumps all kernel state variables (tunables) using `sysctl`.
# This provides an exhaustive snapshot of the live kernel configuration.
# It is extremely useful for deep, low-level troubleshooting of performance
# and stability issues.
#
# Gathers:
#   - The complete output of `sysctl -a`.
#
# Note:
#   - To prevent incorrect FQDN redaction, when in sanitize mode, this
#     function prepends a unique marker to each line. The `run_sanitization`
#     function uses this marker to skip FQDN redaction on these lines and
#     then removes the marker.
#
collect_kernel_env() {
    local LABEL_SYSCTL start_time_block end_time_block duration_block
    STEP_NUM=$((STEP_NUM + 1)); LABEL_SYSCTL="Kernel Environment (sysctl -a)"
    printf "Step %3d: Running: %-50s" "$STEP_NUM" "$LABEL_SYSCTL" > /dev/tty; start_time_block=$(date +%s)
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "COMMAND (File Step $STEP_NUM): \"$LABEL_SYSCTL\" (NOTE: This output is very large)" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    if [ "$SANITIZE_MODE" = true ]; then
        sysctl -a | sed 's/^/_KERNEL_TUNABLE_::/g' >> "$OUTPUT_FILE" 2>&1
    else
        sysctl -a >> "$OUTPUT_FILE" 2>&1
    fi
    end_time_block=$(date +%s); duration_block=$((end_time_block - start_time_block))
    echo "Duration for $LABEL_SYSCTL: ${duration_block}s" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
    printf "\rStep %3d: Finished: %-50s (%ds)\n" "$STEP_NUM" "$LABEL_SYSCTL" "$duration_block" > /dev/tty
    printf "Step %3d: Pausing for %d seconds after %s...\n" "$STEP_NUM" "$COOLDOWN_SECONDS" "$LABEL_SYSCTL" > /dev/tty; display_status_banner; sleep "$COOLDOWN_SECONDS"
}

declare -a IP_MAP # Associative array to hold IP -> description
IP_MAP_FILE="" # Temp file to hold the map for sed

#
# Builds a temporary file containing a mapping of known IP addresses to
# descriptive labels (e.g., 192.168.1.1 -> [INTERFACE_LAN_IP]).
# This map is used by the `run_sanitization` function to make the final
# sanitized output more readable and contextually useful.
#
# Logic:
#   - Gathers IPs from all network interfaces via `ifconfig`.
#   - Gathers gateway IPs from `configctl`.
#   - Writes a series of `sed` substitution commands to a temporary file.
#
# Note:
#   - This function only runs when the --sanitize flag is active.
#
build_ip_map() {
    if [ "$SANITIZE_MODE" = false ]; then return; fi
    printf "\nBuilding IP address map for sanitization...\n" > /dev/tty
    
    IP_MAP_FILE=$(mktemp)
    # Ensure the temp file is cleaned up on exit
    trap 'rm -f "$IP_MAP_FILE"' EXIT

    # 1. Gather interface IPs (IPv4 and IPv6)
    local ifconfig_output
    ifconfig_output=$(ifconfig -a)
    
    echo "$ifconfig_output" | awk '
        /^[a-zA-Z0-9_]+:/ { iface=$1; sub(/:$/, "", iface) }
        /inet / { ip=$2; print ip "[INTERFACE_" toupper(iface) "_IP]"; }
        /inet6 / { ip=$2; sub(/%.*/, "", ip); print ip "[INTERFACE_" toupper(iface) "_IP6]"; }
    ' | while read -r ip desc; do
        echo "s/[[:<:]]${ip}[[:>:]]/${desc}/g" >> "$IP_MAP_FILE"
    done

    # 2. Gather Gateway IPs
    if [ -x "$CONFIGCTL_CMD" ]; then
        local gw_json
        gw_json=$("$CONFIGCTL_CMD" interface gateways status json 2>/dev/null)
        if [ -n "$gw_json" ] && command -v jq >/dev/null 2>&1; then
            echo "$gw_json" | jq -r '.[]? | select(.address and .address != "~") | "\(.address) \(.name)"' | while read -r ip name; do
                safe_name=$(echo "$name" | tr '[:lower:]' '[:upper:]' | sed 's/[^a-zA-Z0-9_]/_/g')
                desc="[GATEWAY_${safe_name}_IP]"
                echo "s/[[:<:]]${ip}[[:>:]]/${desc}/g" >> "$IP_MAP_FILE"
            done
        fi
    fi

    # 3. Add localhost
    echo "s/[[:<:]]127\.0\.0\.1[[:>:]]/[LOCALHOST_IP]/g" >> "$IP_MAP_FILE"
    echo "s/[[:<:]]::1[[:>:]]/[LOCALHOST_IP6]/g" >> "$IP_MAP_FILE"

    printf "IP map built with %d entries.\n" "$(wc -l < "$IP_MAP_FILE")" > /dev/tty
}

#
# Performs the main sanitization process on the final output file.
# It uses a multi-pass `sed` operation to replace sensitive information
# with redacted placeholders.
#
# Logic:
#   1. Applies the descriptive IP map created by `build_ip_map`.
#   2. Applies a series of generic regexes to redact MAC addresses, FQDNs,
#      any remaining IP addresses, and the hostname.
#   3. Skips FQDN redaction on lines marked as kernel tunables to prevent
#      incorrectly redacting them.
#   4. Removes the kernel tunable markers after other sanitization is complete.
#
# Note:
#   - This function only runs when the --sanitize flag is active.
#
run_sanitization() {
    if [ "$SANITIZE_MODE" = true ]; then
        printf "\nSanitizing output file: %s\n" "$OUTPUT_FILE" > /dev/tty
        local temp_sanitized_file
        temp_sanitized_file=$(mktemp)
        local hostname_val
        hostname_val=$(hostname)

        # Apply the specific IP map first, then the generic patterns
        sed -E -f "$IP_MAP_FILE" \
            -e 's/[[:<:]]([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}[[:>:]]/\1:[REDACTED_MAC_SUFFIX]/g' \
            -e '/^_KERNEL_TUNABLE_::/! s/[[:<:]]([a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}[[:>:]]/[REDACTED_FQDN]/g' \
            -e 's/[[:<:]](25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])[[:>:]]/[REDACTED_IPv4]/g' \
            -e 's/[[:<:]]fd[0-9a-fA-F]{2}:[0-9a-fA-F:]+/[REDACTED_IPv6_ULA]/g' \
            -e 's/[[:<:]]fe80:[0-9a-fA-F:]+/[REDACTED_IPv6_LinkLocal]/g' \
            -e 's/[[:<:]]([23][0-9a-fA-F]{3}:[0-9a-fA-F:]+)[[:>:]]/[REDACTED_IPv6_GUA]/g' \
            -e "s/[[:<:]]${hostname_val}[[:>:]]/[REDACTED_HOSTNAME]/g" \
            -e 's/^_KERNEL_TUNABLE_::(.*)/\1/g' \
            "$OUTPUT_FILE" > "$temp_sanitized_file"

        mv "$temp_sanitized_file" "$OUTPUT_FILE"
        printf "Sanitization of %s complete.\n" "$OUTPUT_FILE" > /dev/tty
    fi
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
    section_start_time=$(date +%s) 
    printf "Starting Section %d: %s\n" "$SECTION_NUM" "$section_desc_name" > /dev/tty
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; printf "SECTION %d: %s\n" "$SECTION_NUM" "$section_desc_name" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    "$section_func_name" # Call the actual collection function
    section_end_time=$(date +%s); section_duration=$((section_end_time - section_start_time))
    printf "Finished Section %d: %s in %ds.\n" "$SECTION_NUM" "$section_desc_name" "$section_duration" > /dev/tty
    echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MINOR" >> "$OUTPUT_FILE"
    echo "Section $SECTION_NUM '$section_desc_name' completed in ${section_duration}s." >> "$OUTPUT_FILE"
done

build_ip_map
run_sanitization

echo "" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"; echo "Diagnostics collection finished." >> "$OUTPUT_FILE"; echo "Output file: $OUTPUT_FILE" >> "$OUTPUT_FILE"; echo "$DIVIDER_MAJOR" >> "$OUTPUT_FILE"
MD5_FILE="${OUTPUT_FILE}.md5"; SHA256_FILE="${OUTPUT_FILE}.sha256"
MD5_HASH=$( (md5 -q "$OUTPUT_FILE" 2>/dev/null || md5sum "$OUTPUT_FILE" 2>/dev/null | awk '{print $1}') || echo "md5_tool_not_found_or_failed")
SHA256_HASH=$( (sha256 -q "$OUTPUT_FILE" 2>/dev/null || sha256sum "$OUTPUT_FILE" 2>/dev/null | awk '{print $1}') || echo "sha256_tool_not_found_or_failed")
echo "$MD5_HASH" > "$MD5_FILE"; echo "$SHA256_HASH" > "$SHA256_FILE"
sync; echo "" > /dev/tty; echo "Diagnostics collection finished. Output saved to $OUTPUT_FILE" > /dev/tty
echo "MD5: $MD5_HASH (saved to $MD5_FILE)" > /dev/tty; echo "SHA256: $SHA256_HASH (saved to $SHA256_FILE)" > /dev/tty
exit 0
