# practicum_project
Network Scanner CLI Tool

A simple Python-based command-line network scanner that provides:

Ping Sweep: Scan a range of IP addresses to find active hosts.

Port Scan with Banner Grabbing: Scan ports on one or multiple hosts and retrieve service banners.

Ping Individual Host: Check if a single host is reachable.

Save Results: Save scan outputs to a file for later review.

Features

  Ping Sweep: Uses ICMP ping to detect live hosts in a subnet.

  Port Scanning: Scans TCP ports in a specified range using socket connections.
  
  Banner Grabbing: Retrieves the first 1024 bytes from an open port to identify services.

  Concurrency: Implements multithreading (ThreadPoolExecutor) for faster scanning.

  CLI Menu: Interactive text menu for selecting scan options.

  Result Saving: Write ping or port scan outputs to a file.

Requirements

  Python 3.6 or newer

  Standard library modules (subprocess, platform, socket, concurrent.futures)

  No external dependencies required.

Installation

  Clone this repository or download the script.

  Ensure you have the correct Python version:

  python3 --version

  Run the script directly:

  python3 server.py

Usage

When you run the script, you will see a menu:

Select an option:
1. Ping Sweep
2. Port Scan with Banner Grabbing / Service Scanning
3. Ping an Individual Host
4. Save Last Scan Results to a File
5. Display Help / Usage
Type 'exit' to quit the program.

Option 1 (Ping Sweep)

Enter the base network (e.g., 192.168.1).

Scans .1 through .254 by default.

Lists active IP addresses.

Option 2 (Port Scan)

Sub-options:

  a. Scan a single IP.

  b. Perform a ping sweep then scan a subnet.

  c. Scan results from the last ping sweep.

Specify start and end ports.

Displays open/closed ports and any retrieved banners.

Option 3 (Ping Individual Host)

Enter a single IP to test.

Option 4 (Save Results)

Save the most recent scan results (list or dict) to a file.

Option 5 (Help/Usage)

Re-displays this help text.
