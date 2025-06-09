# OPNsense Comprehensive Diagnostics Script (`opn-diag.sh`)

`opn-diag.sh` is a comprehensive, non-intrusive diagnostics and data collector designed specifically for the OPNsense® firewall platform. Its primary function is to gather a wide array of system, hardware, network, firewall, service, and configuration information and save it into a set of well-structured, timestamped files.

The collected data is intended to aid in troubleshooting complex issues, performing system health checks, or providing detailed information for support purposes without altering the system's configuration.

## Features

* **Comprehensive Data Collection**: Gathers detailed information across 19 distinct diagnostic sections, from system info and hardware details to firewall rules and network connectivity.

* **Sanitization Mode**: Includes a `--sanitize` flag to redact sensitive information (IP addresses, MACs, hostnames, serial numbers) from the output, making it safe to share.
	
	* **Dynamic & Modular**: The script's execution flow is controlled by arrays, making it easy for developers to reorder, add, or remove diagnostic sections without breaking the script's structure.

* **Detailed Logging & Timestamps**: Every command is logged with its full output, exit status, and execution duration. Each major section's cumulative execution time is also calculated and logged.

* **User-Friendly Output**:

    * **Index of Sections**: The main output file begins with a clickable index, allowing for easy navigation to any specific section in a large log file.

    * **Live Console Feedback**: Provides clean, real-time progress updates to the terminal as the script runs.

* **Externalized Checksums**: Generates separate `.md5` and `.sha256` files to verify the integrity of the main output log without altering it.

* **Graceful Degradation**: The script intelligently checks for optional dependencies (`jq`, `lscpu`, `drill`, etc.) and skips relevant tests gracefully if they are not installed, providing a suggestion to install them.

* **Targeted Captures**: Includes specialized data captures, such as a `tcpdump` that excludes common web traffic to highlight other protocols.

## Requirements

* **Operating System**: OPNsense® / FreeBSD

* **Required Shell**: GNU Bash (`/usr/local/bin/bash`). The script is not compatible with `sh`.

* **Required Privileges**: **Root user**. The script will exit if not run with UID 0.

* **Optional Dependencies**: For maximum data collection, the following utilities are recommended:

    * `jq` (for robust JSON parsing)

    * `lscpu`, `lsblk` (`pkg install sysinfo`)

    * `drill` (`pkg install ldns`)

    * `mtr` (`pkg install mtr-nox11`)

    * `dmidecode` (`pkg install dmidecode`)

## Installation & Usage

### Step 1: Download the Script

Clone this repository or download the `opn-diag.sh` script to your OPNsense firewall, for example, in the `/root` directory.

### Step 2: Make the Script Executable

Open a shell on your OPNsense machine (e.g., via SSH) and run the following command:

`chmod +x opn-diag.sh`

### Step 3: Run the Script

As the root user, execute the script using bash:

`bash ./opn-diag.sh`
	
### Command-line Options

*   **`--sanitize`**: Runs the script in sanitization mode. This will redact sensitive information from the output file, including IP addresses (v4/v6), MAC addresses, FQDNs, hostnames, and disk serial numbers. The resulting file is generally safe to share for public troubleshooting.

`bash ./opn-diag.sh --sanitize`


The script will print live progress to the terminal and inform you when it has finished.

## Output Files

The script will generate three files in the directory where it was run, all sharing the same timestamp:

1.  **`opnsense_diagnostics_output_[timestamp].txt`**: The main, verbose log file containing all collected diagnostic data.

2.  **`opnsense_diagnostics_output_[timestamp].txt.md5`**: A text file containing only the MD5 hash of the main log file.

3.  **`opnsense_diagnostics_output_[timestamp].txt.sha256`**: A text file containing only the SHA256 hash of the main log file.

### Structure of the Main Output File

The main `.txt` log file is structured for readability:

* **Header**: Contains the script version, execution date, and OPNsense version.

* **Initial Checks**: Logs the presence and permissions of required utilities.

* **Index of Sections**: A table of contents listing all diagnostic sections and their corresponding section numbers. You can search for `SECTION X:` to jump to a specific part of the report.

* **Diagnostic Sections**: Each section follows a consistent format:

    * A major header (e.g., `SECTION 1: System Information`).

    * A series of command blocks for each step within that section.

    * Each command block clearly states the step number, the descriptive label for the command, the exact command string that was run, its full output, its exit status, and its duration.

    * A summary at the end of each section stating its total execution time.

* **Footer**: A final confirmation that the script has finished.

## Collected Data Sections

The script currently collects the following sections in order:

1.  **System Information**: `uname`, FreeBSD version, uptime, boot messages, OPNsense system status, and sensor data.

2.  **Hardware Diagnostics**: CPU info (`lscpu`), block devices (`lsblk`), hardware status (`hwstat`), `dmidecode` for system and BIOS info, disk list (`geom`), and `smartctl` health status for all disks.

3.  **Interface Configuration & Status**: Verbose `ifconfig`, `configctl` interface summaries and stats, CARP status, and recent kernel messages related to networking.

4.  **Routing Table & ARP**: `netstat` routing tables, routing statistics, ARP and NDP tables, and `configctl` gateway status.

5.  **ARP Timeout Configuration**: System-wide ARP settings from `sysctl`.

6.  **DNS Configuration & Resolution**: `resolv.conf`, configured nameservers, DNS service status (Unbound/Dnsmasq), socket status, and `drill` tests for external and local hostnames.

7.  **Firewall (PF) Diagnostics**: Verbose `pfctl` output for rules, NAT, states, info, and tables.

8.  **Network Connections & Services**: `netstat` and `sockstat` for active sockets and protocol statistics, plus mbuf usage and interrupt stats.

9.  **System Logs**: The last 100-200 lines from key OPNsense logs (system, filter, routing, resolver, dhcpd, ntpd).

10. **Connectivity Tests (General)**: `ping`, `traceroute`, and `mtr` tests to common internet hosts (e.g., 8.8.8.8).

11. **TCPDump Non-Web Traffic**: A short packet capture on the WAN interface that filters out standard HTTP/HTTPS traffic (ports 80/443) to highlight other protocols.

12. **OPNsense Health & Disk Space**: `configctl` health checks, firmware status, disk usage (`df`), ZFS pool status, and partition layout.

13. **Package Information & Integrity**: Lists installed packages and performs a system integrity check with `pkg check`.

14. **WAN Gateway Connectivity & Health**: Iterates through all configured gateways, determines the correct interface and source IP, and performs a targeted `ping` test to check reachability, latency, and packet loss.

15. **Running Processes Snapshot**: A snapshot of the current process list from `top`.

16. **NTP/Time Service Status**: Status of `ntpd`/`chronyd` and peer information.

17. **OPNsense Services Status**: A list and status of all services managed by `configctl`.

18. **Key Configuration Files**: The content of important system configuration files (e.g., `/etc/hosts`, `/etc/fstab`, etc.).

19. **Kernel Environment (sysctl)**: A full dump of all kernel state variables from `sysctl -a`.

## Contributing

Contributions are welcome! Please feel free to submit a pull request.

When developing, please adhere to the following project standards:

* All shell code must be compatible with GNU Bash and should not rely on `sh`.

* All lines in the `opn-diag.sh` script file should attempt to be no more than 80 characters wide.

* Follow the modular design by adding new functionality in self-contained `collect_*` functions and adding them to the main execution arrays.

