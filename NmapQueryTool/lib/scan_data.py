import re

from .nmap_data import NmapData
from .host_data import HostData
from .port_data import PortData

class ScanData(NmapData):

    def __init__(self):
        self.host_data_by_ip = {} # Mapping of IP addresses to HostData objects

    def __getitem__(self, ip):
        self.host_data_by_ip[ip]

    def __str__(self):
        lines = []
        for ip in self.host_data_by_ip:
            lines.append(str(self.host_data_by_ip[ip]))

        return '\n'.join(lines)

    def get_headers(self):
        headers = HostData.DEFAULT_HOST_DATA_COLUMNS + PortData.PORT_DATA_COLUMNS
        for ip in self.host_data_by_ip:
            for key in self.host_data_by_ip[ip].additional_service_info:
                header_value = key.upper()
                if not header_value in headers:
                    headers.append(header_value)
                
        return headers

    def to_csv_string(self):
        rows = []
        headers = self.get_headers()
        rows.append(','.join(headers))

        for ip in self.host_data_by_ip:
            host_data = self.host_data_by_ip[ip]
            host_data_records = host_data.to_list_of_records()
            for record in host_data_records:
                record_row_data  = []
                # Iterate over the headers in order to ensure that the
                # data in the final CSV rows will be in the correct column
                for header in headers:
                    if header in record:
                        record_row_data.append(record[header])
                    else:
                        record_row_data.append('')

                rows.append(','.join(record_row_data))

        return '\n'.join(rows)

    def ips(self):
        return self.host_data_by_ip.keys()

    def host_data_list(self):
        return self.host_data_by_ip.values()        

    def add_host_data(self, host_ip, host_data):
        # TODO: Add logic for merging HostData objects
        if host_ip in self.host_data_by_ip:
            raise Exception('Host data already exists for %s' % host_ip)
        else:
            self.host_data_by_ip[host_ip] = host_data

    def query_by_port(self, port_numbers):
        results_data = ScanData()

        for ip in self.host_data_by_ip:
            result_host_data = self.host_data_by_ip[ip].filter_by_port(port_numbers)
            if result_host_data != None:
                results_data.add_host_data(ip, result_host_data)

        return results_data

    def query_by_ip(self, ip_addresses):
        results_data = ScanData()

        for ip in self.host_data_by_ip:
            if ip in ip_addresses:
                results_data.add_host_data(ip, self.host_data_by_ip[ip].clone())

        return results_data

    def query_by_cidr(self, cidr_blocks):
        # TODO: Implement
        raise Exception('Querying by CIDR block is not currently supported')

    def query_by_os(self, os_list):
        results_data = ScanData()

        for ip in self.host_data_by_ip:
            host_data = self.host_data_by_ip[ip]
            if host_data.os_is_any_of(os_list):
                results_data.add_host_data(ip, host_data.clone())

        return results_data

    def query_by_device_prefix(self, device_prefixes):
        results_data = ScanData()

        for ip in self.host_data_by_ip:
            host_data = self.host_data_by_ip[ip]
            if host_data.device_type_is_any_of(device_prefixes):
                results_data.add_host_data(ip, host_data.clone())

        return results_data

    def save(self, filename, style = 'default'):
        if style == 'default':
            write_to_file(filename, str(self))
        elif style == 'csv':
            write_to_file(filename, self.to_csv_string())
        else:
            raise Exception("'%s' is not a supported output format" % style)

    def count_records(self):
        return len(self.host_data_by_ip.keys())

    def print_data(self):
        print(str(self))

    @staticmethod
    def create_from_nmap_data(data_source):
        scan_data = ScanData()

        for line in data_source:
            if re.match('Nmap scan report for .*', line):
                host_and_ip_data = re.match('Nmap scan report for (.*)', line).group(1)

                # Handles the following two types of line formats:
                #
                # Nmap scan report for 10.90.78.103
                # Nmap scan report for atsva9078153.vbschools.com (10.90.78.153)
                host_ip = None
                hostname = None
                if re.match('([0-9]{1,3}\.){3}[0-9]{1,3}', host_and_ip_data):
                    host_ip = host_and_ip_data
                else:
                    host_ip_pair = host_and_ip_data.replace('(', '').replace(')', '').split(' ')
                    hostname = host_ip_pair[0]
                    host_ip = host_ip_pair[1]
                    
                if host_ip == None:
                    raise Exception('No host IP found if "%s"') % line

                scan_data.add_host_data(host_ip, HostData(host_ip, hostname))

            if re.match('[0-9]+/[a-zA-Z]+[ ]+.*', line):
                tokens = line.strip().split(' ')
                values = [t for t in tokens if t != ''] # Filter out the whitespace tokens

                # Expected format: ['port/protocol', 'state', 'service', 'version (will possibly be multiple tokens)']
                # Example: ['22/tcp', 'open', 'ssh', 'OpenSSH', '6.2', '(protocol', '2.0;', 'Cisco', 'NX-OS)']
                port_number = None
                protocol = None

                if '/' in values[0]:
                    port_and_protocol = values[0].split('/')

                    port_number = port_and_protocol[0]
                    protocol = port_and_protocol[1]
                else:
                    port_number = values[0]

                port_data = PortData(port_number, protocol)
                port_data.state = values[1]
                port_data.service = values[2]
                port_data.version = ' '.join(values[3:])
    
                scan_data.host_data_by_ip[host_ip].add_data(port_data)

            elif re.match('OS details\: (.*)', line):
                result = re.match('OS details\: (.*)', line)
                os_info = result.group(1).replace(' or ', ' ').split(',')
                scan_data.host_data_by_ip[host_ip].add_os_data(os_info)
                
            elif re.match('Service Info: (.*)', line):
                result = re.match('Service Info: (.*)', line)
                service_info_str = result.group(1)

                key_value_pair_strs = service_info_str.split(';')

                for kv_str in key_value_pair_strs:
                    kv_pair = kv_str.split(': ')
                    service_info_key = kv_pair[0].strip()
                    service_info_value = kv_pair[1].strip()

                    if ',' in service_info_value:
                        service_info_value = service_info_value.split(', ')

                    scan_data.host_data_by_ip[host_ip].add_service_info_data(service_info_key, service_info_value)

            else:
                # Skip parsing lines that do not contain relevant data
                continue

        return scan_data
     
