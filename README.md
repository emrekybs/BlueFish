![EmreKybs](https://img.shields.io/badge/MadeBy-Emrekybs-blue)
# BlueFish

<img src="https://github.com/emrekybs/BlueFish/blob/main/bluefish.png" width="250">

BlueFish is a Python-based automation tool designed to simplify the analysis of PCAP (Packet Capture) files. It leverages the power of Wireshark's command-line tool, tshark, to extract valuable information from network captures. With BlueFish, you can quickly identify potential login attempts, analyze network traffic patterns, and extract various network artifacts.

## KEY FEATURES:
* Runs various Tshark commands against a folder containing pcap files (it will only grab .pcaps)
* Creates a main output folder, each unique .pcap file will have a designated folder created where results will be saved.
* Extracts potential login attempts and credentials.
* Analyzes IP and MAC addresses.
* Retrieves embedded objects from network traffic.
* Identifies email addresses and HTTP requests.
* Provides insights into protocols, DNS queries, ICMP packets, SMB operations, FTP sessions, and TLS handshakes.

BlueFish streamlines the process of PCAP analysis, making it easier for security professionals and network analysts to gain insights into network activities.

## INSTALLATION STEPS
      $ git clone https://github.com/emrekybs0/BlueFish.git
      $ cd BlueFish
      (you will need to have tshark installed)
      $ python3 BlueFish.py -f path/to/folder/of/pcaps -p int (4 is default)

## HELP
```
usage: BlueFish.py [-h] -f FOLDER [-p PROCESSES]

Automate pcap analysis for multiple files.

options:
  -h, --help            show this help message and exit
  -f FOLDER, --folder FOLDER
                        Folder containing .pcap files for analysis.
  -p PROCESSES, --processes PROCESSES
                        Number of parallel processes to use.
```     

## RESULTS:
Below are the created folders that contain one or more files with analysis output.
```
* Addresses
* Credentials
* DNS
* DNS_Info
* Emails
* FTP_Sessions
* Headers_Banners
* Hostnames
* HTTP_Requests
* HTTP_Requests_and_Responses
* ICMP_Packets
* IP_Info
* Logins
* MAC_Addresses
* Objects
* Open_Ports
* Protocols
* SMB_Operations
* Software_Versions
* TLS_Handshakes
* Unknown_Traffic
```
