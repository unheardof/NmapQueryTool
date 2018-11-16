# NMAP Query Tool
Post-processor for nmap output that allows fast, simple filtering of data both interactively and inline (i.e. via a bash pipe).

```bash
Usage: python nmap-query.py [-h] [-p PORTS] [-a IPS] [-os OS] [-d DEVICE_TYPE] [-c] [-i NMAP_SCAN_RESULTS_FILE] [-o OUTPUT_FILENAME] [-q]

        Note: the nmap scan results can be provided either through an input file or from STDIN (through a pipe)

        Example: nmap -sV 10.0.0.0/24 | python nmap-query.py -q



[-h | --help]: Will print the help/usage message

[-p | --ports] PORTS: specify one or more (open) ports to filter on. The following input formats are accepted:

        Single port number: -p 22
        Set of port numbers: -p 22,80,443

[-a | --ip-addrs] IPS: specify one or more IP addresses on which to filter. The following input formats are accepted:

        Single IP: -a 10.0.0.1
        Set of IPs: -a 10.0.0.1,10.0.0.2,10.0.0.3
        Single CIDR block: -a 10.0.0.0/24
        Set of CIDR blocks: -a 10.0.0.0/24,10.0.1.0/24
        Range of IPs: -a 10.0.0.1-4

[-os | --operating-system] OS: specify one or more operating systems on which to filter. The following input formats are accepted:

        Single operating system: -os Windws
        Set of operating systems: -os Windows,Linux

[-d | --device-type] DEVICE_TYPE: specify one or more device types on which to filter. The following input formats are accepted:

        Single device type: -d router
        Set of device types: -d router,switch

[-c | --output-csv]: use CSV as the output format

[-i | --input-file] NMAP_SCAN_RESULTS_FILE: specify the name of the input file (i.e. the file which contains the results of the Nmap scan)

[-o | --output-file] OUTPUT_FILENAME: specify the name of the output file

[-q | --query-mode]: enter the interactive query mode
```
