

import nmap

def main():
    print("=== Simple Python Nmap Scanner ===\n")

    # Ask the user for target IP
    target_ip = input("Enter the target host IP address: ")

    # Create Nmap scanner object
    scanner = nmap.PortScanner()

    print(f"\nScanning {target_ip}... Please wait.\n")

    try:
        # Run a simple scan on the target (top 1000 ports)
        scanner.scan(target_ip, arguments='-T4 -F')

        # Show the results
        for host in scanner.all_hosts():
            print(f"Host: {host}")
            print(f"State: {scanner[host].state()}")
            for proto in scanner[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    print(f"Port {port}: {scanner[host][proto][port]['state']}")
    
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
