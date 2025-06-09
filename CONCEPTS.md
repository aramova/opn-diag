# OPN-Diag Script: Concepts and Troubleshooting Guide

This document provides a granular breakdown of the `opn-diag.sh` script, its design concepts, the logic behind each diagnostic test, and how to use the output for troubleshooting OPNsense firewall and network issues.

## Core Design Concepts

This section covers the foundational principles behind the script's architecture.

The `opn-diag.sh` script is designed to be a comprehensive, portable, and safe tool for gathering critical system and network information from an OPNsense firewall. Its core design is guided by the following principles:

1.  **Modularity and Maintainability**:
    *   **Functional Decomposition**: The script is broken down into a series of `collect_*` functions (e.g., `collect_system_info`, `collect_hardware_diagnostics`). Each function is responsible for a specific domain of diagnostics. This makes the script easier to read, modify, and extend. New diagnostic sections can be added simply by creating a new function and adding it to the `SECTION_FUNCTIONS` array.
    *   **Centralized Execution Logic**: The main loop iterates through the `SECTION_FUNCTIONS` and `SECTION_DESCRIPTIVE_NAMES` arrays. This centralizes the control flow, ensuring that every section is executed in a consistent order and that timing/logging is handled uniformly.
    *   **Helper Functions**: Common tasks like executing a command (`execute_cmd`), checking for a binary's existence (`execute_if_binary_exists`), or printing a file's content (`cat_if_exists`) are encapsulated in their own helper functions. This promotes code reuse and reduces redundancy.

2.  **Robustness and Portability**:
    *   **Dependency Checks**: The `perform_initial_checks` function verifies the existence and executability of essential binaries at the start. For non-essential but useful tools (like `lscpu`, `mtr`, `jq`), the script gracefully skips the corresponding tests and suggests the appropriate package to install, rather than failing.
    *   **Shell Compatibility**: The script uses `#!/usr/local/bin/bash` and adheres to `bash`-compatible syntax It avoids `sh` (Bourne shell) specific limitations and uses features like arrays for better structure.
    *   **OS/Tool Variant Awareness**: The code accounts for differences between BSD and GNU userland tools where possible. For example, the `sed` commands for sanitization use `[[:<:]]` and `[[:>:]]` for word boundaries, which are more portable than `\b`.

3.  **User Experience and Feedback**:
    *   **Clear TTY Progress**: The script provides real-time feedback to the user's terminal (TTY). It shows which section and step is currently running, how long it took, and its exit status.
    *   **Single-Line Updates**: By using carriage returns (`\r`), the script updates the status of a step on a single line, preventing the screen from being flooded with "Running..." and "Finished..." messages.
    *   **Distinct Output File**: All diagnostic data is redirected to a single, timestamped text file (`opnsense_diagnostics_output_YYYYMMDD_HHMMSS.txt`). This separates the clean progress view on the TTY from the verbose data capture.
    *   **Sanitization Banner**: A persistent banner at the top of the screen immediately informs the user whether the final output will be sanitized or not, preventing accidental sharing of sensitive data.

4.  **Safety and Data Integrity**:
    *   **Sanitization as a Core Feature**: The `--sanitize` flag provides a crucial safety mechanism. It allows a user to generate a log file that is safe to share publicly or with support personnel, as it redacts sensitive information like IP addresses, MAC addresses, and hostnames.
    *   **Descriptive Sanitization**: The sanitization logic goes beyond simple redaction. It attempts to map known IP addresses (interfaces, gateways) to descriptive labels like `[INTERFACE_WAN_IP]` or `[GATEWAY_GW_WAN_IP]`. This preserves the contextual value of the data for troubleshooting without revealing the actual sensitive values.
    *   **Output Hashing**: After the output file is generated, the script calculates and saves its MD5 and SHA256 hashes. This allows for verification that the file has not been altered or corrupted after its creation.

5.  **Comprehensive Data Collection**:
    *   **Layered Approach**: The script gathers data from multiple layers of the system: hardware (`dmidecode`, `smartctl`), kernel (`sysctl`, `dmesg`), operating system (`uname`, `netstat`), and the OPNsense application layer (`configctl`, `opnsense-log`).
    *   **OPNsense-Specific Tooling**: The script heavily leverages OPNsense's built-in `configctl` command-line utility. This is the preferred way to get structured, reliable information about the firewall's configuration and status, as it queries the live configuration directly.
    *   **Fallback Mechanisms**: Where possible, the script has fallbacks. For example, if it cannot determine the WAN interface for `tcpdump` from `configctl`, it falls back to parsing the output of `netstat` to find the default route's interface.

## Diagnostic Sections Breakdown
---

### Section 3: Interface Configuration & Status (`collect_interface_config`)

*   **Logic and Purpose**: This is one of the most critical sections for network troubleshooting. It gathers detailed information about the configuration, status, and statistics of all network interfaces.
*   **Commands Executed**:
    *   `ifconfig -a -vv`: Provides a highly verbose output for every network interface. It shows MAC addresses, IP addresses (v4 and v6), subnet masks, interface flags (e.g., `UP`, `RUNNING`, `PROMISC`), MTU size, and media information (e.g., speed and duplex).
    *   `configctl interface list ifconfig`, `... show interfaces`, `... list stats`: These OPNsense commands provide the firewall's view of the interfaces, which can be useful to compare against the kernel's view from `ifconfig`. They show assigned names (e.g., 'WAN', 'LAN'), device names (e.g., 'em0'), and detailed statistics.
    *   `netstat -i -n -d -h -W`: Displays statistics for all network interfaces, including packet counts (input/output), error counts (input/output), and drops. The `-W` flag provides wider fields for interface names.
    *   `dmesg -a | tail -n 500`: Shows the most recent kernel messages. This is repeated here to catch any recent interface-related events, like link flaps (a link going up and down repeatedly).
    *   `configctl interface show carp`: Shows the status of CARP (Common Address Redundancy Protocol) interfaces, which is essential for diagnosing high-availability (HA) cluster problems.
*   **Troubleshooting Use Cases**:
    *   **Problem**: The WAN interface has no connectivity.
    *   **Analysis**: Check `ifconfig` for the WAN interface. Does it have a public IP address? Are the `UP` and `RUNNING` flags present? If `RUNNING` is missing, it indicates a physical layer problem (bad cable, modem/ISP issue). Check `netstat -i` for mounting input/output errors (`Ierrs`/`Oerrs`), which can indicate a faulty NIC, cable, or driver issue.
    *   **Problem**: Users on the LAN are experiencing slow network speeds.
    *   **Analysis**: Check `ifconfig` for the LAN interface's media settings. Does it show the expected speed (e.g., `1000baseT <full-duplex>`)? If it has negotiated a lower speed (e.g., 100baseT), it points to a cabling or switch port problem. High error or collision counts in `netstat -i` also point to physical layer issues.
    *   **Problem**: In an HA cluster, the backup firewall is not taking over when the primary fails.
    *   **Analysis**: The `configctl interface show carp` output on both firewalls is crucial. It will show the status of each CARP VIP (`MASTER` or `BACKUP`). If both think they are `MASTER`, you have a split-brain scenario, likely caused by a network issue preventing them from communicating multicast CARP advertisements.

---

### Section 4: Routing Table & ARP (`collect_routing_arp`)

*   **Logic and Purpose**: This section inspects the networking layer (Layer 3) of the OSI model. It checks the firewall's "road map" (the routing table) and its address book for directly connected devices (the ARP and NDP tables).
*   **Commands Executed**:
    *   `netstat -r -n -A -W`: Displays the kernel's routing tables for all address families. The `-n` prevents slow DNS lookups. This is the definitive source for where the firewall will send traffic destined for any IP address.
    *   `configctl interface routes list`: Shows the routes as configured and understood by OPNsense. Comparing this with `netstat -r` can reveal discrepancies.
    *   `arp -a -n`: Shows the ARP (Address Resolution Protocol) table, which maps Layer 3 (IP) addresses to Layer 2 (MAC) addresses for IPv4. This is how the firewall finds devices on the local network segments.
    *   `configctl interface list arp` & `... list ndp`: OPNsense commands to view the ARP and NDP (Neighbor Discovery Protocol, for IPv6) tables.
    *   `configctl interface gateways status`: Provides the real-time status of all configured gateways, including latency and loss, which is critical for multi-WAN troubleshooting.
*   **Troubleshooting Use Cases**:
    *   **Problem**: A user on the LAN cannot access the internet.
    *   **Analysis**: Check the routing table (`netstat -r`). Is there a `default` route? Does it point to the correct WAN gateway IP? If the default route is missing, the firewall doesn't know where to send internet-bound traffic. Then, check the `arp -a` table. Does the firewall have a MAC address entry for the user's client IP? Does it have an entry for the WAN gateway's IP? A missing ARP entry for the gateway means the firewall can't even send traffic to the modem.
    *   **Problem**: In a multi-WAN setup, traffic is not failing over to the backup connection.
    *   **Analysis**: Examine `configctl interface gateways status`. Is the primary gateway shown as `offline`? Is the backup gateway `online`? Check the routing table to see if the `default` route has correctly switched to the backup gateway.

---

### Section 5: ARP Timeout Configuration (`collect_arp_timeouts`)

*   **Logic and Purpose**: This is a small but important check of kernel parameters related to ARP. Incorrect ARP timeouts can sometimes cause stale entries and lead to intermittent connectivity issues, especially in environments with many devices.
*   **Commands Executed**:
    *   `sysctl net.link.ether.inet`: Displays kernel settings related to ARP, such as `arptimeout` (how long an entry stays in the cache) and `maxtries` (how many times it tries to resolve an address).
*   **Troubleshooting Use Cases**:
    *   **Problem**: A specific device on the network occasionally becomes unreachable for a few minutes.
    *   **Analysis**: If a device (e.g., a printer with power-saving features) doesn't respond to ARP requests while asleep, its entry might expire from the firewall's ARP table. If the `arptimeout` is very short, this can happen frequently. Comparing these values to their defaults can help identify if a non-standard configuration is contributing to the problem.

---

### Section 6: DNS Configuration & Resolution (`collect_dns_resolution`)

*   **Logic and Purpose**: This section is dedicated to one of the most common sources of network problems: DNS. It checks the system's DNS configuration, the status of local DNS services (Unbound/Dnsmasq), and performs live resolution tests.
*   **Commands Executed**:
    *   `cat /etc/resolv.conf`: Shows which DNS servers the firewall itself is using for its own lookups.
    *   `configctl system list nameservers`: Shows the DNS servers configured in the OPNsense GUI (System -> Settings -> General). These are the servers that Unbound or Dnsmasq will forward queries to.
    *   `pgrep -lf unbound` & `pgrep -lf dnsmasq`: Checks if the Unbound or Dnsmasq processes are running.
    *   `unbound-control status`, `configctl unbound stats`: Provides detailed statistics from the Unbound DNS resolver, including cache hits/misses, memory usage, and queries per type.
    *   `drill -V 4 google.com`: Performs a live DNS lookup for `google.com`. This is a fundamental test to see if the firewall can resolve external domains.
    *   `drill -V 4 $(hostname)`: Tries to resolve the firewall's own hostname. Tests internal DNS resolution.
    *   `configctl unbound listlocalzones` & `drill` loop: This block intelligently finds all locally-served DNS zones from Unbound and then attempts to `drill` each one, verifying that local DNS overrides are working correctly.
*   **Troubleshooting Use Cases**:
    *   **Problem**: Users report "The internet is down," but you can ping external IPs like `8.8.8.8` from the firewall.
    *   **Analysis**: This classic symptom almost always points to DNS failure. Check the output of `drill google.com`. If it fails, the problem is with the firewall's upstream DNS servers. Check `configctl system list nameservers` to see what they are. Check `pgrep -lf unbound` to ensure the local DNS service is running. If it is, its logs (Section 9) are the next place to look.
    *   **Problem**: You have a local override for `myserver.local` to point to a private IP, but clients are getting a public IP instead.
    *   **Analysis**: Look at the "Testing Local Unbound Zones" block. Did the script test `myserver.local`? Did the `drill` output show the correct private IP? If not, it indicates a misconfiguration in the Unbound DNS Overrides section of the OPNsense GUI.

## Sanitization Logic


### Section 1: System Information (`collect_system_info`)

*   **Logic and Purpose**: This section gathers high-level information about the operating system and its status. It establishes a baseline understanding of the software environment.
*   **Commands Executed**:
    *   `uname -a`: Prints detailed OS information, including the kernel version, architecture, and build date. Essential for identifying the base FreeBSD version.
    *   `freebsd-version -ukr`: Shows the installed userland, kernel, and running kernel versions. Helps spot mismatches that can occur after an update.
    *   `uptime`: Shows how long the system has been running, the number of users, and the system load averages. A recent reboot could be a sign of a crash. High load averages point to performance issues.
    *   `cat /var/run/dmesg.boot`: Dumps the kernel message buffer from boot time. This is invaluable for diagnosing hardware detection issues, driver failures, or other problems that occur very early in the boot process.
    *   `configctl system status`: An OPNsense-specific command to get a quick, structured overview of the system's health, including versions and service status.
    *   `configctl system sensors`: Queries the system's hardware sensors for temperature, voltage, and fan speed. Critical for diagnosing overheating or hardware power issues.
*   **Troubleshooting Use Cases**:
    *   **Problem**: The firewall is crashing randomly.
    *   **Analysis**: Check `uptime` to see if the crashes coincide with specific times. Review `dmesg.boot` and `configctl system sensors` for signs of hardware errors or overheating that could cause instability.
    *   **Problem**: A new network card is not working.
    *   **Analysis**: Search the `dmesg.boot` output for the card's model or the driver name. If it shows errors during initialization or isn't detected at all, it points to a driver or hardware compatibility issue.

---

### Section 2: Hardware Diagnostics (`collect_hardware_diagnostics`)

*   **Logic and Purpose**: This section probes the physical hardware of the system. It's designed to identify issues with the CPU, memory, storage, and motherboard.
*   **Commands Executed**:
    *   `lscpu`: Lists detailed CPU information, including model, cores, speed, and features.
    *   `lsblk`: Lists block devices (disks). Useful for seeing all detected storage devices.
    *   `hwstat`: Provides a general hardware status overview.
    *   `dmidecode -q -t system` & `dmidecode -q -t bios`: Queries the DMI (or SMBIOS) data to get the system manufacturer, model number, serial number, and BIOS/UEFI version. Invaluable for identifying the exact hardware and checking for firmware updates.
    *   `geom disk list`: Shows detailed information about disk geometry and attached disks from the FreeBSD GEOM framework.
    *   `smartctl -a /dev/...`: Runs a full Self-Monitoring, Analysis, and Reporting Technology (SMART) check on each detected disk. This can reveal a failing or unhealthy disk before it fails completely.
*   **Troubleshooting Use Cases**:
    *   **Problem**: The system is performing poorly or has I/O errors in the logs.
    *   **Analysis**: Examine the output of `smartctl`. Look for non-zero values in `Reallocated_Sector_Ct`, `Current_Pending_Sector`, or a `FAILED` status in the overall health assessment. These are strong indicators of a failing disk.
    *   **Problem**: You need to confirm if a system's BIOS/UEFI is out of date.
    *   **Analysis**: The `dmidecode -t bios` output shows the current firmware version and release date. This can be compared against the manufacturer's website to see if an update is available, which might fix stability or compatibility issues.
    *   **Sample `smartctl` Output Snippet**:
        ```
        SMART Attributes Data Structure revision number: 10
        ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
          5 Reallocated_Sector_Ct   0x0033   100   100   005    Pre-fail  Always       -       0
          9 Power_On_Hours          0x0032   099   099   000    Old_age   Always       -       12345
        197 Current_Pending_Sector  0x0022   100   100   000    Old_age   Always       -       8
        ```
    *   **Interpretation**: In this sample, the `Current_Pending_Sector` count of 8 indicates there are sectors the drive firmware is unsure about. This is a warning sign that the disk may be developing problems.

## Sanitization Logic

This section details how the `--sanitize` flag works to protect sensitive information while keeping the output useful for diagnostics.
