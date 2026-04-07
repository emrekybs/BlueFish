import subprocess
import os
import argparse
from multiprocessing import Pool


def run_tshark_command(command, output_file=None):
    # Ensure column headers are included if '-T fields' is used
    if '-T fields' in command and '-E header=y' not in command:
        command += ' -E header=y'
    
    try:
        if output_file:
            with open(output_file, 'w') as file:
                subprocess.run(command, shell=True, stdout=file, stderr=subprocess.PIPE)
        else:
            subprocess.run(command, shell=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e.stderr.decode()}")

def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)


def remove_file_if_empty(file_path):
    if os.path.exists(file_path) and os.path.getsize(file_path) == 0:
        os.remove(file_path)

def analyze_pcap_task(args):
    """Wrapper for multiprocessing: processes a single .pcap file."""
    pcap_file, output_folder = args
    analyze_pcap(pcap_file, output_folder)

def analyze_pcap(pcap_file, output_folder):
    print(f"Analyzing {pcap_file}...")

    # Headers and Banners (HTTP, FTP, SSH, TLS, etc.)
    headers_dir = os.path.join(output_folder, "Headers_Banners")
    create_directory(headers_dir)
    # Extract HTTP headers
    run_tshark_command(f"tshark -Y 'http' -T fields -e http.request.method -e http.host -e http.user_agent -e http.response.code -e http.server -r {pcap_file}",
                       os.path.join(headers_dir, 'http_headers.txt'))
    # Extract generic banners for FTP, SSH, Telnet, and other text-based protocols
    run_tshark_command(f"tshark -Y 'ftp or ssh or telnet or smtp or pop or imap' -T fields -e text -r {pcap_file}",
                       os.path.join(headers_dir, 'protocol_banners.txt'))
    # Extract TLS handshake banners
    run_tshark_command(f"tshark -Y 'ssl.handshake' -T fields -e ssl.handshake.version -e ssl.handshake.ciphersuite -r {pcap_file}",
                       os.path.join(headers_dir, 'tls_banners.txt'))
    # Extract other potential protocol banners
    run_tshark_command(f"tshark -T fields -e frame.protocols -e text -r {pcap_file}",
                       os.path.join(headers_dir, 'generic_protocol_banners.txt'))

    # Open Ports
    ports_dir = os.path.join(output_folder, "Open_Ports")
    create_directory(ports_dir)
    run_tshark_command(f"tshark -Y 'tcp or udp' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -r {pcap_file}",
                       os.path.join(ports_dir, 'ports.txt'))

    # Credentials and Passwords
    credentials_dir = os.path.join(output_folder, "Credentials")
    create_directory(credentials_dir)
    run_tshark_command(f"tshark -Y 'ftp or http.authbasic or telnet or smtp.auth' -T fields -e ip.src -e ip.dst -e text -r {pcap_file}",
                       os.path.join(credentials_dir, 'credentials.txt'))
    run_tshark_command(f"tshark -r {pcap_file} | grep -i -E 'auth|denied|login|user|usr|password|pass|pw|logon|key|cipher|token'",
                       os.path.join(credentials_dir, 'keywords.txt'))

    # DNS Information
    dns_dir = os.path.join(output_folder, "DNS_Info")
    create_directory(dns_dir)
    run_tshark_command(f"tshark -Y 'dns' -T fields -e dns.qry.name -e dns.a -e dns.aaaa -e dns.resp.ttl -r {pcap_file}",
                       os.path.join(dns_dir, 'dns_records.txt'))

    # Software Versions
    software_dir = os.path.join(output_folder, "Software_Versions")
    create_directory(software_dir)
    run_tshark_command(f"tshark -Y 'ssl.handshake or http or ssh or ftp or telnet' -T fields -e ssl.handshake.version -e ssl.handshake.ciphersuite -e http.server -e text -r {pcap_file}",
                       os.path.join(software_dir, 'software_versions.txt'))

    # Hostnames
    hostnames_dir = os.path.join(output_folder, "Hostnames")
    create_directory(hostnames_dir)
    run_tshark_command(f"tshark -Y 'dns or http.host' -T fields -e dns.qry.name -e http.host -r {pcap_file}",
                       os.path.join(hostnames_dir, 'hostnames.txt'))

    # IP and MAC Addresses
    addresses_dir = os.path.join(output_folder, "Addresses")
    create_directory(addresses_dir)
    run_tshark_command(f"tshark -Y 'ip or eth' -T fields -e ip.src -e ip.dst -e eth.src -e eth.dst -r {pcap_file} | sort | uniq",
                       os.path.join(addresses_dir, 'ip_mac_addresses.txt'))

    # Protocols Observed
    protocols_dir = os.path.join(output_folder, "Protocols")
    create_directory(protocols_dir)
    run_tshark_command(f"tshark -r {pcap_file} -T fields -e frame.protocols | sort | uniq -c | sort -n -r",
                       os.path.join(protocols_dir, 'protocols.txt'))

    # Capture Unknown or Non-Standard Traffic
    unknown_dir = os.path.join(output_folder, "Unknown_Traffic")
    create_directory(unknown_dir)
    run_tshark_command(f"tshark -Y 'tcp.analysis.retransmission or udp.length > 512' -T fields -E header=y -e ip.src -e ip.dst -e frame.len -e tcp.seq -e udp.length -r {pcap_file}",
                       os.path.join(unknown_dir, 'unknown_traffic.txt'))

    # Logins
    logins_dir = os.path.join(output_folder, "Logins")
    create_directory(logins_dir)
    run_tshark_command(f"tshark -Y 'ftp or http.authbasic or telnet or smtp.auth' -T fields -e ip.src -e ip.dst -e text -r {pcap_file}",
                       os.path.join(logins_dir, 'possible_logins.txt'))
    run_tshark_command(f"tshark -Q -z credentials -r {pcap_file}", os.path.join(logins_dir, 'credentials.txt'))

    # IP Info
    ip_info_dir = os.path.join(output_folder, "IP_Info")
    create_directory(ip_info_dir)
    run_tshark_command(f"tshark -T fields -e ip.src -e ip.dst -e ip.proto -r {pcap_file} | sort | uniq -c | sort -n -r", 
                       os.path.join(ip_info_dir, 'all_addresses.txt'))
    run_tshark_command(f"tshark -T fields -e ip.src -r {pcap_file} | sort | uniq -c | sort -n -r", 
                       os.path.join(ip_info_dir, 'source_addresses.txt'))
    run_tshark_command(f"tshark -T fields -e ip.dst -r {pcap_file} | sort | uniq -c | sort -n -r", 
                       os.path.join(ip_info_dir, 'destination_addresses.txt'))

    # MAC Addresses
    mac_dir = os.path.join(output_folder, "MAC_Addresses")
    create_directory(mac_dir)
    run_tshark_command(f"tshark -z endpoints,eth -r {pcap_file}", os.path.join(mac_dir, 'mac_addresses.txt'))

    # Objects
    objects_dir = os.path.join(output_folder, "Objects")
    create_directory(objects_dir)
    object_types = ["http", "smb", "tftp", "ftp", "imap", "smtp", "pop3", "dicom", "imf", "ntfs"]
    for obj_type in object_types:
        run_tshark_command(f"tshark --export-objects {obj_type},{objects_dir} -r {pcap_file}")

    # Emails
    emails_dir = os.path.join(output_folder, "Emails")
    create_directory(emails_dir)
    run_tshark_command(f"tshark -Y 'smtp or pop or imap' -T fields -e text -r {pcap_file} | grep -E '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,6}}\\b'", 
                       os.path.join(emails_dir, 'email_packets.txt'))

    # HTTP Requests
    http_requests_dir = os.path.join(output_folder, "HTTP_Requests")
    create_directory(http_requests_dir)
    run_tshark_command(f"tshark -Y 'http.request.method' -T fields -e http.request.method -e http.host -e http.user_agent -r {pcap_file}", 
                       os.path.join(http_requests_dir, 'http_requests.txt'))

    # Protocols
    protocols_dir = os.path.join(output_folder, "Protocols")
    create_directory(protocols_dir)
    run_tshark_command(f"tshark -T fields -e frame.protocols -r {pcap_file} | sort | uniq -c | sort -n -r", 
                       os.path.join(protocols_dir, 'protocols.txt'))

    # DNS Queries
    dns_dir = os.path.join(output_folder, "DNS")
    create_directory(dns_dir)
    run_tshark_command(f"tshark -Y 'dns' -T fields -e dns.qry.name -e dns.a -e dns.aaaa -e dns.resp.ttl -r {pcap_file} | sort | uniq", 
                       os.path.join(dns_dir, 'dns_queries.txt'))

    # HTTP Requests and Responses
    http_request_dir = os.path.join(output_folder, "HTTP_Requests_and_Responses")
    create_directory(http_request_dir)
    run_tshark_command(f"tshark -Y 'http' -T fields -e http.request.method -e http.host -e http.request.uri -e http.response.code -e http.content_length -r {pcap_file} | sort | uniq", 
                       os.path.join(http_request_dir, 'http_requests_and_responses.txt'))

    # ICMP Packets
    icmp_dir = os.path.join(output_folder, "ICMP_Packets")
    create_directory(icmp_dir)
    run_tshark_command(f"tshark -Y 'icmp' -T fields -e ip.src -e ip.dst -e icmp.type -e icmp.code -e icmp.seq -r {pcap_file}", 
                       os.path.join(icmp_dir, 'icmp_packets.txt'))

    # SMB Operations
    smb_dir = os.path.join(output_folder, "SMB_Operations")
    create_directory(smb_dir)
    run_tshark_command(f"tshark -Y 'smb' -T fields -e smb.cmd -e smb.file -e smb.tree -r {pcap_file}", 
                       os.path.join(smb_dir, 'smb_operations.txt'))

    # FTP Sessions
    ftp_dir = os.path.join(output_folder, "FTP_Sessions")
    create_directory(ftp_dir)
    run_tshark_command(f"tshark -Y 'ftp' -T fields -e ftp.request.command -e ftp.response.code -e ftp.data -r {pcap_file}", 
                       os.path.join(ftp_dir, 'ftp_sessions.txt'))

    # TLS Handshakes
    tls_dir = os.path.join(output_folder, "TLS_Handshakes")
    create_directory(tls_dir)
    run_tshark_command(f"tshark -Y 'tls.handshake' -T fields -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite -r {pcap_file}", 
                       os.path.join(tls_dir, 'tls_handshakes.txt'))


    # Clean up empty files
    for dirpath, dirnames, filenames in os.walk(output_folder):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            remove_file_if_empty(file_path)

    print(f"Analysis complete for {pcap_file}. Results saved to {output_folder}.")


def main():
    parser = argparse.ArgumentParser(description="Automate pcap analysis for multiple files.")
    parser.add_argument('-f', '--folder', required=True, help="Folder containing .pcap files for analysis.")
    parser.add_argument('-p', '--processes', type=int, default=4, help="Number of parallel processes to use.")
    args = parser.parse_args()

    input_folder = args.folder
    num_processes = args.processes

    if not os.path.exists(input_folder):
        print(f"Error: The folder {input_folder} does not exist.")
        return

    # Create base output directory
    base_output_dir = "BlueFish_Results"
    create_directory(base_output_dir)

    # Prepare tasks for multiprocessing
    tasks = []
    for file in os.listdir(input_folder):
        if file.endswith(".pcap"):
            pcap_file = os.path.join(input_folder, file)
            output_folder = os.path.join(base_output_dir, os.path.splitext(file)[0])
            create_directory(output_folder)
            tasks.append((pcap_file, output_folder))
        else:
            print(f"Skipping unsupported file: {file}")

    # Run tasks in parallel
    with Pool(processes=num_processes) as pool:
        pool.map(analyze_pcap_task, tasks)

    print(f"All pcap analyses completed. Results saved in {base_output_dir}.")


if __name__ == "__main__":
    main()
