import subprocess
import platform
import socket
from concurrent.futures import ThreadPoolExecutor

# Function to ping a host and return the IP if it responds.
def ping_host(ip, ping_count=1, timeout=3):
    # Determine the correct flag based on the OS.
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(ping_count), ip]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if result.returncode == 0:
            print(f"Host {ip} is up")
            return ip  # Return the active IP address.
        else:
            print(f"Host {ip} is down")
            return None
    except subprocess.TimeoutExpired:
        print(f"Host {ip} did not respond within {timeout} seconds")
        return None
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return None

# Function to perform a ping sweep on a base network.
def ping_sweep(network, start=1, end=255, ping_count=1):
    if not network.endswith('.'):
        network += '.'
    ips = [f"{network}{i}" for i in range(start, end)]
    active_ips = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(ping_host, ip, ping_count) for ip in ips]
    for future in futures:
        result = future.result()
        if result is not None:
            active_ips.append(result)
    return active_ips

# Function to scan a single port on a given IP.
def scan_port(ip, port, timeout=1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        except Exception:
            return False

# Function to grab the banner from an open port.
def grab_banner(ip, port, timeout=3):
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                # Try to receive up to 1024 bytes of data.
                banner = s.recv(1024).decode().strip()
            except socket.timeout:
                banner = ""
    except Exception as e:
        print(f"Error grabbing banner from {ip}:{port} - {e}")
    return banner

# Function to perform a port scan on one target IP with banner grabbing.
def port_scan_target(ip, start_port, end_port, timeout=1):
    open_ports = []
    print(f"\nScanning ports on {ip}:")
    with ThreadPoolExecutor(max_workers=100) as executor:
        # Submit a scan for each port in the specified range.
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in range(start_port, end_port + 1)}
        for future in futures:
            port = futures[future]
            if future.result():
                print(f"Port {port} is open on {ip}")
                open_ports.append(port)
                # Attempt to grab the banner for service identification.
                banner = grab_banner(ip, port)
                if banner:
                    print(f"Banner for {ip}:{port}: {banner}")
                else:
                    print(f"No banner received for {ip}:{port}")
            else:
                print(f"Port {port} is closed on {ip}")
    if not open_ports:
        print(f"No open ports found on {ip} within the range {start_port}-{end_port}.")
    return open_ports

# Function to scan a range of ports for multiple IP addresses.
def port_scan_for_ips(ips, start_port, end_port, timeout=1):
    results = {}
    for ip in ips:
        open_ports = port_scan_target(ip, start_port, end_port, timeout)
        results[ip] = open_ports
    return results

# Function to save the scan results to a file.
def save_results_to_file(results, filename):
    try:
        with open(filename, 'w') as f:
            # If results is a dictionary (from port scans):
            if isinstance(results, dict):
                for ip, ports in results.items():
                    f.write(f"{ip}: {ports}\n")
            # If results is a list (from ping sweep or single host):
            elif isinstance(results, list):
                for item in results:
                    f.write(f"{item} is responding\n")
            else:
                f.write(str(results))
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving results: {e}")

# Main CLI interface in a loop.
def main():
    global last_scan_results
    while True:
        print("\nSelect an option:")
        print("1. Ping Sweep")
        print("2. Port Scan with Banner Grabbing / Service Scanning")
        print("3. Ping an Individual Host")
        print("4. Save Last Scan Results to a File")
        print("5. Display Help / Usage")
        print("Type 'exit' to quit the program.")
        option = input("Enter option (1-5 or exit): ").strip()
        
        if option.lower() == "exit":
            print("Exiting the program...")
            break

        if option == "1":
            # Perform a ping sweep.
            network = input("Enter the base network IP (e.g., 192.168.1): ")
            print(f"Scanning network: {network}.1 to {network}.254")
            last_scan_results = ping_sweep(network)
            print("\nActive IP addresses found:")
            for ip in last_scan_results:
                print(ip)
                
        elif option == "2":
            print("Port Scan Options:")
            print("a. Scan a specific IP")
            print("b. Scan a base network IP (perform a ping sweep first)")
            print("c. Scan active IP addresses from a ping sweep")
            sub_option = input("Enter option (a, b, or c): ").strip().lower()
            
            if sub_option == "a":
                # Scan a single IP address.
                ip = input("Enter the target IP: ").strip()
                start_port = int(input("Enter start port: "))
                end_port = int(input("Enter end port: "))
                last_scan_results = {ip: port_scan_target(ip, start_port, end_port)}
                
            elif sub_option in ("b", "c"):
                network = input("Enter the base network IP for the ping sweep (e.g., 192.168.1): ")
                print(f"Performing ping sweep on {network}.1 to {network}.254 to identify active hosts...")
                active_ips = ping_sweep(network)
                if active_ips:
                    print("\nActive IP addresses found:")
                    for ip in active_ips:
                        print(ip)
                    start_port = int(input("Enter start port for scan: "))
                    end_port = int(input("Enter end port for scan: "))
                    last_scan_results = port_scan_for_ips(active_ips, start_port, end_port)
                else:
                    print("No active IP addresses found.")
            else:
                print("Invalid option for port scan.")
                
        elif option == "3":
            # Ping a single host.
            ip = input("Enter the IP address to ping: ").strip()
            result = ping_host(ip)
            if result:
                print(f"{ip} responded to the ping.")
                last_scan_results = [ip]
            else:
                print(f"{ip} did not respond to the ping.")
                last_scan_results = []
                
        elif option == "4":
            # Save the last scan results to a file.
            if last_scan_results:
                filename = input("Enter filename to save results (e.g., results.txt): ").strip()
                save_results_to_file(last_scan_results, filename)
            else:
                print("No scan results to save. Please run a scan first.")
                
        elif option == "5":
            # Display help/usage information.
            print("Usage Information:\n"
                  "1. Ping Sweep: Scans a network for active hosts.\n"
                  "2. Port Scan: Scans ports on an IP or set of IPs with banner grabbing for service identification.\n"
                  "3. Ping an Individual Host: Checks a single host's responsiveness.\n"
                  "4. Save Results: Saves the last scan output to a file (this can be a list or a dictionary).\n"
                  "5. Help/Usage: Displays this help information.\n"
                  "Type 'exit' at any time to quit the program.")
        else:
            print("Invalid option selected.")

if __name__ == "__main__":
    last_scan_results = None
    main()
