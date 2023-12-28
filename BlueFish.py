import subprocess
import os
from tkinter import filedialog
from tkinter import messagebox
from tkinter import Tk


def start_program():
   
    def draw_banner():
        banner = """
\033[94m┌──────────────────────────────────────┐
│                                      │
│               ><(((º>                │
│  				       │
│        Automate pcap analysis        │
│				       │	
│            +--BlueFish--+            │
└──────────────────────────────────────┘\033[0m
        """
        return banner

   
    banner_text = draw_banner()
    print(banner_text)

    # Metin
    author_info = """
\033[94mAuthor By Emre Koybasi
Github: https://github.com/emrekybs\033[0m
    """
    print(author_info)

    
    input("Press Enter to start BlueFish......")


start_program()
def run_tshark_command(command, output_file=None):
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


root = Tk()
root.withdraw() 

if messagebox.askyesno("BlueFish", "Hello from BlueFish! \nReady to dive into pcap analysis?"):
    pcap_file = filedialog.askopenfilename(title="Choose the pcap file for analysis.", filetypes=[("Pcap files", "*.pcap")])
    if pcap_file:
        print("\033[34mBlueFish is currently analyzing your pcap file and will convey the results shortly...\033[0m")


        base_dir = "BlueFish"
        create_directory(base_dir)

        # Logins
        logins_dir = os.path.join(base_dir, "Logins")
        create_directory(logins_dir)
        run_tshark_command(f"tshark -r {pcap_file} | grep -i -E 'auth|denied|login|user|usr|success|psswd|pass|pw|logon|key|cipher|sum|token|pin|code|fail|correct|restrict'", os.path.join(logins_dir, 'possible_logins.txt'))
        run_tshark_command(f"tshark -Q -z credentials -r {pcap_file}", os.path.join(logins_dir, 'credentials.txt'))

        # IP Info
        ip_info_dir = os.path.join(base_dir, "IP_Info")
        create_directory(ip_info_dir)
        run_tshark_command(f"tshark -Q -r {pcap_file} -T fields -e ip.src -e ip.dst | grep -o '[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}' | sort | uniq -c | sort -n -r", os.path.join(ip_info_dir, 'all_addresses.txt'))
        run_tshark_command(f"tshark -Q -r {pcap_file} -T fields -e ip.src | grep -o '[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}' | sort | uniq -c | sort -n -r", os.path.join(ip_info_dir, 'source_addresses.txt'))
        run_tshark_command(f"tshark -Q -r {pcap_file} -T fields -e ip.dst | grep -o '[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}' | sort | uniq -c | sort -n -r", os.path.join(ip_info_dir, 'destination_addresses.txt'))

        # MAC Addresses
        mac_dir = os.path.join(base_dir, "MAC_Addresses")
        create_directory(mac_dir)
        run_tshark_command(f"tshark -Q -nqr {pcap_file} -z endpoints,eth", os.path.join(mac_dir, 'mac_addresses.txt'))

        # Objects
        objects_dir = os.path.join(base_dir, "Objects")
        create_directory(objects_dir)
        object_types = ["imf", "dicom", "smb", "tftp", "http"]
        for obj_type in object_types:
            run_tshark_command(f"tshark -Q -r {pcap_file} --export-objects {obj_type},{objects_dir}")

        # Emails
        emails_dir = os.path.join(base_dir, "Emails")
        create_directory(emails_dir)
        run_tshark_command(f"tshark -Q -r {pcap_file} -T fields -e text | grep -E '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,6}}\\b'", os.path.join(emails_dir, 'verbose_email_packets.txt'))

        # HTTP Requests
       	http_requests_dir = os.path.join(base_dir, "HTTP_Requests")
        create_directory(http_requests_dir)
        run_tshark_command(f"tshark -Vr {pcap_file} | grep -Eo '(GET|POST|HEAD) .* HTTP/1.[01]|Host: .*' | sort | uniq -c | sort -n", os.path.join(http_requests_dir, 'http_requests.txt'))

        # Protocols
        protocols_dir = os.path.join(base_dir, "Protocols")
        create_directory(protocols_dir)
        run_tshark_command(f"tshark -r {pcap_file} -T fields -e frame.protocols | sort | uniq -c | sort -n -r", os.path.join(protocols_dir, 'protocols.txt'))

        # DNS Queries
        Dns_dir = os.path.join(base_dir, "Dns")
        create_directory(Dns_dir)
        run_tshark_command(f"tshark -r {pcap_file} -Y 'dns' -T fields -e dns.qry.name | sort | uniq", os.path.join(Dns_dir, 'dns_queries.txt'))

        # HTTP Requests and Responses
        httprequest_dir = os.path.join(base_dir, "http_requests_and_responses")
        create_directory(httprequest_dir)
        run_tshark_command(f"tshark -r {pcap_file} -Y 'http' -T fields -e http.request.method -e http.host -e http.request.uri -e http.response.code | sort | uniq", os.path.join(httprequest_dir, 'http_requests_and_responses.txt'))

        # ICMP Packets
        icmp_dir = os.path.join(base_dir, "ICMP_Packets")
        create_directory(icmp_dir)
        run_tshark_command(f"tshark -r {pcap_file} -Y 'icmp' -T fields -e ip.src -e ip.dst -e icmp.type -e icmp.code", os.path.join(icmp_dir, 'icmp_packets.txt'))

        # SMB Operations
        smb_dir = os.path.join(base_dir, "ICMP_Packets")
        create_directory(smb_dir)
        run_tshark_command(f"tshark -r {pcap_file} -Y 'smb' -T fields -e smb.cmd -e smb.file", os.path.join(smb_dir, 'smb_operations.txt'))

        # FTP Sessions
        ftp_dir = os.path.join(base_dir, "FTP_Sessions")
        create_directory(ftp_dir)
        run_tshark_command(f"tshark -r {pcap_file} -Y 'ftp' -T fields -e ftp.request.command -e ftp.response.code", os.path.join(ftp_dir, 'ftp_sessions.txt'))

        # TLS Handshakes
        tls_dir = os.path.join(base_dir, "TLS_Handshakes")
        create_directory(tls_dir)
        run_tshark_command(f"tshark -r {pcap_file} -Y 'tls.handshake.type' -T fields -e tls.handshake.type", os.path.join(tls_dir, 'tls_handshakes.txt'))
        
        
        for dirpath, dirnames, filenames in os.walk(base_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                remove_file_if_empty(file_path)

        messagebox.showinfo("BlueFish", "Pcap analysis complete. Check the 'BlueFish' directory for results.")
