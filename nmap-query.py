import sys, getopt, re, os, csv

# Note: this script is Python 3.6 compatible only (i.e. no Python 2.7 support)

DIVIDER = '--------------------------------------------------------------------------------'

DEFAULT_OUTPUT_FILE = 'nmap_results_parsed.csv'

OPTIONS_DEFINITIONS = [
        {
            'short': 'h',
            'long': 'help',
            'value_name': None,
            'usage_msg': '[-h | --help]: Will print the help/usage message\n'
        },
        {
            'short': 'p',
            'long': 'ports',
            'value_name': 'PORTS',
            'usage_msg': '[-p | --ports] PORTS: specify one or more (open) ports to filter on. The following input formats are accepted:\n\n\tSingle port number: -p 22\n\tSet of port numbers: -p 22,80,443\n'
        },
        {
            'short': 'a',
            'long': 'ip-addrs',
            'value_name': 'IPS',
            'usage_msg': '[-a | --ip-addrs] IPS: specify one or more IP addresses on which to filter. The following input formats are accepted:\n\n\tSingle IP: -a 10.0.0.1\n\tSet of IPs: -a 10.0.0.1,10.0.0.2,10.0.0.3\n\tSingle CIDR block: -a 10.0.0.0/24\n\tSet of CIDR blocks: -a 10.0.0.0/24,10.0.1.0/24\n\tRange of IPs: -a 10.0.0.1-4\n'

        },
        {
            'short': 'os',
            'long': 'operating-system',
            'value_name': 'OS',
            'usage_msg': '[-os | --operating-system] OS: specify one or more operating systems on which to filter. The following input formats are accepted:\n\n\tSingle operating system: -os Windws\n\tSet of operating systems: -os Windows,Linux\n'

        },
        {
            'short': 'd',
            'long': 'device-type',
            'value_name': 'DEVICE_TYPE',
            'usage_msg': '[-d | --device-type] DEVICE_TYPE: specify one or more device types on which to filter. The following input formats are accepted:\n\n\tSingle device type: -d router\n\tSet of device types: -d router,switch\n'

        },
        {
            'short': 'c',
            'long': 'output-csv',
            'value_name': None,
            'usage_msg': '[-c | --output-csv]: use CSV as the output format\n'
        },
        {
            'short': 'i',
            'long': 'input-file',
            'value_name': 'NMAP_SCAN_RESULTS_FILE',
            'usage_msg': '[-i | --input-file] NMAP_SCAN_RESULTS_FILE: specify the name of the input file (i.e. the file which contains the results of the Nmap scan)\n'
        },
        {
            'short': 'o',
            'long': 'output-file',
            'value_name': 'OUTPUT_FILENAME',
            'usage_msg': '[-o | --output-file] OUTPUT_FILENAME: specify the name of the output file\n'
        },
        {
            'short': 'q',
            'long': 'query-mode',
            'value_name': None,
            'usage_msg': '[-q | --query-mode]: enter the interactive query mode\n'
        },
    ]

PORT_QUERY_PROMPT_MSG = 'What port(s) are you interested in?'
PORT_QUERY_HELP_MSG = '\n'.join([
    'To get all results for a specific port, for example port 22, type "22"',
    'To get all results with a specific set of ports, such as 22 and 80, type "22, 80"'
])

IP_QUERY_PROMPT_MSG = 'What IP address(es) are you interested in?'
IP_QUERY_HELP_MSG = '\n'.join([
    'To get all results with a specific IP, for example 10.0.0.1, type "10.0.0.1"',
    'To get all results with a specific set of IP addresses, for example 10.0.0.1 and 10.0.0.2, type "10.0.0.1, 10.0.0.2"',
    'To get all results in a specific range of IP addresses, type "10.0.0.0/24"',
    'To get all results for a set of IP ranges, type "10.0.0.0/24, 10.1.0.0/24"'
])

OS_QUERY_PROMPT_MSG = 'What OS version(s) are you interested in?'
OS_QUERY_HELP_MSG = '\n'.join([
    'To get all results with a specific OS version, for example Windows, type "Windows"; you can also be more specific (e.g. "Windows Server 2008 R2")',
    'To get all results with any of a set of OS versions, for example Windows Server 2008 R2 and Linux, type "Windows Server 2008 R2, Linux"'
])

DEVICE_QUERY_PROMPT_MSG = 'What device type(s) are you interested in?'
DEVICE_QUERY_HELP_MSG = '\n'.join([
    'To get all devices of a specific type, for example switches, type "switch" (note that you should *not* use the plural form)',
    'To get all devices which are any of a set of types, for example routers and switches, type "switch, router"'
])

class PortData:
    PORT_DATA_COLUMNS = ['PORT NUMBER', 'PROTOCOL', 'STATE', 'SERVICE', 'VERSION']

    def __init__(self, port_number, protocol = None):
        if port_number == None or port_number.strip() == '':
            raise Exception('Must provide a port number when creating a PortData object')

        self.port_number = port_number
        self.protocol = protocol
        self.state = None # Will be 'open', 'closed', or 'filtered'
        self.service = None
        self.version = None

    def __str__(self):
        tokens = [self.port_number]
        tokens.append(value_as_str(self.protocol))
        tokens.append(value_as_str(self.state))
        tokens.append(value_as_str(self.service))
        tokens.append(value_as_str(self.version))

        return ' '.join(tokens)

    def clone(self):
        new_port_data = PortData(self.port_number, self.protocol)
        new_port_data.state = self.state
        new_port_data.service = self.service
        new_port_data.version = self.version

        return new_port_data

class HostData:

    DEFAULT_HOST_DATA_COLUMNS = ['IP', 'HOSTNAME', 'OS', 'DEVICE TYPE']

    def __init__(self, ip, hostname = None):
        if ip == None or ip.strip() == '':
            raise Exception('Must provide an IP address when creating a HostData object')

        self.ip = ip
        self.hostname = hostname
        self.os_list = []
        self.device_types = []
        self.additional_service_info = {} # Mapping of nmap service info key to list of values
        self.data_by_port_number = {} # Mapping of port number strings to PortData objects

    def __str__(self):
        lines = []

        lines.append('Host IP: %s' % self.ip)

        if self.hostname != None:
            lines.append('Hostname: %s' % self.hostname)

        if len(self.os_list) != 0:
            lines.append('OS(s): %s' % ', '.join(self.os_list))

        if len(self.device_types) != 0:
            lines.append('Device Type(s): %s' % ', '.join(self.device_types))

        for key in self.additional_service_info:
            if type(self.additional_service_info[key]) == list:
                value_str = ','.join(self.additional_service_info[key])
            else:
                value_str = self.additional_service_info[key]

            lines.append('%s: %s' % (key, value_str))

        # This line is just for formatting
        lines.append('')

        for port_number in self.data_by_port_number:
            lines.append(str(self.data_by_port_number[port_number]))

        # These lines are just for formatting
        lines.append(DIVIDER)
        lines.append('')

        return '\n'.join(lines)

    # Will return a list of dictionaries, with each dictionary containing
    # all of the data for a single row / record in the ultimate output report
    def to_list_of_records(self):
        records = []
        base_dict = {}

        base_dict['IP'] = value_as_str(self.ip)
        base_dict['HOSTNAME'] = value_as_str(self.hostname)
        base_dict['OS'] = '; '.join(self.os_list)
        base_dict['DEVICE TYPE'] = '; '.join(self.device_types)

        for key in self.additional_service_info:
            value_str = None
            if type(self.additional_service_info[key]) == list:
                value_str = ','.join(self.additional_service_info[key])
            else:
                value_str = self.additional_service_info[key]

            base_dict[key.upper()] = value_str

        # 'IP', 'HOSTNAME', 'OS', 'DEVICE TYPE', 'PORT NUMBER', 'PROTOCOL', 'STATE', 'SERVICE', 'VERSION'

        # TODO: Remove
        # base_columns = []
        # base_columns.append(self.ip)
        # base_columns.append(value_as_str(self.hostname))
        # base_columns.append('; '.join(self.os_list))
        # base_columns.append('; '.join(self.device_types))

        for port in self.data_by_port_number:
            # Create a copy of the base_dict to prevent editing that dictionary directly
            data_dict = base_dict.copy()
            port_data = self.data_by_port_number[port]

            data_dict['PORT NUMBER'] = value_as_str(port_data.port_number)
            data_dict['PROTOCOL'] = value_as_str(port_data.protocol)
            data_dict['STATE'] = value_as_str(port_data.state)
            data_dict['SERVICE'] = value_as_str(port_data.service)

            # Escape any comma's in the service version
            data_dict['VERSION'] = value_as_str(port_data.version.replace(',', ''))

            records.append(data_dict)

        return records

    def clone(self):
        new_host_data = HostData(self.ip, self.hostname)
        new_host_data.os_list = self.os_list
        new_host_data.device_types = self.device_types
        new_host_data.additional_service_info = self.additional_service_info
        new_host_data.data_by_port_number = {}
        
        for port in self.data_by_port_number:
            new_host_data.data_by_port_number[port] = self.data_by_port_number[port].clone()

        return new_host_data

    def add_data(self, port_data):
        if port_data.port_number in self.data_by_port_number:
            # TODO: Add functionality for merging PortData objects
            raise Exception("Data already exists for port %s on host %s" % port_data.port_number, self.ip)
        else:
            self.data_by_port_number[port_data.port_number] = port_data

    def add_os_data(self, os_data):
        if type(os_data) is list:
            self.os_list += os_data
        elif type(os_data) is str:
            self.os_list.append(os_data)
        else:
            raise Exception("Unknown / unsupported data type encountered")

    def add_device_data(self, device_data):
        if type(device_data) is list:
            self.device_types += device_data
        elif type(device_data) is str:
            self.device_types.append(device_data)
        else:
            raise Exception("Unknown / unsupported data type encountered")

    def add_service_info_data(self, key, value):
        if key in ('OS', 'OSs'):
            self.add_os_data(value)
        elif key in ('Device', 'Devices'):
            self.add_device_data(value)
        if key in self.additional_service_info:
            if not value in self.additional_service_info[key]:
                self.additional_service_info[key].append(value)

    def filter_by_port(self, port_numbers, state = 'open'):
        filtered_host_data = self.clone()
       
        match_found = False
        new_data_by_port_number = {}
        for port in self.data_by_port_number:
            if port in port_numbers:
                port_data = self.data_by_port_number[port]
                if port_data.state == state:
                    match_found = True

                    print('Clone of port data for port %s: %s' % (port, str(port_data.clone())))
                    new_data_by_port_number[port] = port_data.clone()

        filtered_host_data.data_by_port_number = new_data_by_port_number

        if match_found:
            return filtered_host_data
        else:
            return None

    def os_is_any_of(self, os_prefix_list):
        match_found = False
        for os in self.os_list:
            if any_prefix_matches(os, os_prefix_list):
                match_found = True
                break

        return match_found

    def device_type_is_any_of(self, device_prefix_list):
        match_found = False
        for device_type in self.device_types:
            if any_prefix_matches(device_type, device_prefix_list):
                match_found = True
                break

        return match_found

class ScanData:

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
            for key in self.additional_service_info:
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
        self.host_data_by_ip.keys()

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

    def query_by_os_prefix(self, os_prefixes):
        results_data = ScanData()

        for ip in self.host_data_by_ip:
            host_data = self.host_data_by_ip[ip]
            if host_data.os_is_any_of(os_prefixes):
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
        # TODO: Remove
        print("Style: %s" % style)
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

    # TODO: Add other query operations

class InteractionContext:
    def __init__(self, scan_data):
        self.scan_data = scan_data
        self.quit = False
        self.results = scan_data
        self.return_to_previous = False 

    def print_count(self):
        if self.results == None:
            print('\nNo results are available\n')
        else:
            print('\nResults Count: %d\n' % self.results.count_records())

    def print_results(self):
        if self.results == None or self.results.count_records() == 0:
            print('\nResuls set is empty\n')
        else:
            print('\n%s' % DIVIDER)
            print('Results')
            print('%s\n\n' % DIVIDER)
            print(self.results)

    # TODO: Add support for saving both in plaintext table format (current) and CSV
    def save(self):
        if self.results == None: 
            print('\nThere is nothing to save\n')
        else:
            while True:
                response = input('\nWhat would you like the output file to be called?\n\n')

                if response in ('back', 'previous'):
                    return

                filename = response
                if os.path.exists(filename):
                    response = input('\nFile "%s" already exists; do you want to overwrite it (y/n)?\n\n' % filename)
                    if response == 'y':
                        write_to_file(filename, str(self.results))
                        break
                    else:
                        continue
                else:
                    write_to_file(filename, str(self.results))
                    break

def value_as_str(value):
    if value == None:
        return ''

    return value

def prep_option(opt_definition):
    opt_str = "[-%s" % (opt_definition['short'])
    if opt_definition['value_name'] != None:
        opt_str += " %s" % (opt_definition['value_name'])

    opt_str += "]"
    return opt_str

def usage_msg():
    options = [prep_option(definition) for definition in OPTIONS_DEFINITIONS]

    lines = []
    lines.append("")
    lines.append("Tool for extracting specific information from Nmap scan results")
    lines.append("")
    lines.append("")
    lines.append("Usage: python nmap-query.py %s" % (" ".join(options)))
    lines.append("")
    lines.append("\tNote: the nmap scan results can be provided either through an input file or from STDIN (through a pipe)")
    lines.append("")
    lines.append("\tExample: nmap -sV 10.0.0.0/24 | python nmap-query.py -q")
    lines.append("")
    lines.append("")
    lines.append("")
    lines += [definition['usage_msg'] for definition in OPTIONS_DEFINITIONS]
    lines.append("")

    return '\n'.join(lines)

# Used to prepare short options for the getopt.getopt
def prep_short_option(opt_definition):
    opt_str = opt_definition['short']
    if opt_definition['value_name']:
        opt_str += ":"

    return "".join(opt_str)

# Used to prepare long options for the getopt.getopt
def prep_long_option(opt_definition):
    opt_str = opt_definition['long']
    if opt_definition['value_name']:
        opt_str += "="

    return opt_str

def short_opt_string():
    short_options = [definition['short'] for definition in OPTIONS_DEFINITIONS]
    return short_options

def print_usage_and_exit(exit_code):
    print(usage_msg())
    sys.exit(exit_code)

def write_to_file(filename, content):
    with open(filename, 'w') as f:
        f.write(content)

def handle_input(prompt, help_msg, context):
    while True:
        response = input('\n%s\n\n' % prompt)
        if response == 'quit':
            context.quit = True # Break out of the interactive query loop
            break

        if response == 'help':
            print('\n%s\n' % help_msg)
        elif response == 'save':
            context.save()
        elif response == 'count':
            context.print_count()
        elif response == 'results':
            context.print_results()
        elif response in ('back', 'previous'):
            context.return_to_previous = True
            break
        else:
            break

    return response, context

# TODO: Ensure the provided filter string is valid
def parse_filter_string(str):
    # Allow "22,33,44" and "22, 33, 44" (and "22,33, 44")
    return [s.strip() for s in str.split(',')]

def any_prefix_matches(string, prefixes):
    for prefix in prefixes:
        if string.startswith(prefix):
            return True

    return False

# TODO: Incorporate hostname (when available)
def create_results_line(ip, port, port_info):
    # IP: PORT PROTOCOL STATE SERVICE VERSION
    return '%s: %s %s %s %s %s' % (ip, port, port_info['protocol'], port_info['state'], port_info['service'], port_info['version'])


def handle_port_query(context):
    response, context = handle_input(PORT_QUERY_PROMPT_MSG, PORT_QUERY_HELP_MSG, context)

    if context.quit or context.return_to_previous:
        context.return_to_previous = False
        return context

    ports = parse_filter_string(response)
    context.results = context.scan_data.query_by_port(ports)
    context.print_results()

    return context

# TODO: Add support for compound queries (i.e. filter by IP and port)
# TODO: Add support for arbitrary IP ranges (e.g. 10.0.0.1-4) in addition to CIDR blocks (and update the help message for this query type accordingly)
# TODO: Add support for IPv6
def handle_ip_query(context):
    response, context = handle_input(IP_QUERY_PROMPT_MSG, IP_QUERY_HELP_MSG, context)

    if context.quit or context.return_to_previous:
        context.return_to_previous = False
        return context

    ips = parse_filter_string(response)
    context.results = context.scan_data.query_by_ip(ips)
    context.print_results()

    return context    

def handle_os_query(context):
    response, context = handle_input(OS_QUERY_PROMPT_MSG, OS_QUERY_HELP_MSG, context)

    if context.quit or context.return_to_previous:
        context.return_to_previous = False
        return context

    target_os_prefixes = parse_filter_string(response)
    context.results = context.scan_data.query_by_os_prefix(target_os_prefixes)
    context.print_results()

    return context

def handle_device_query(context):
    response, context = handle_input(DEVICE_QUERY_PROMPT_MSG, DEVICE_QUERY_HELP_MSG, context)

    if context.quit or context.return_to_previous:
        context.return_to_previous = False
        return context

    target_device_prefixes = parse_filter_string(response)
    context.results = context.scan_data.query_by_device_prefix(target_device_prefixes)
    context.print_results()

    return context

def handle_queries(data):
    print('\n%s' % DIVIDER)
    print("Entering query mode\n")
    print("The following commands can be used at any time:\n")
    print("'quit': exits the program")
    print("'help': gets help")
    print("'back' or 'previous': go back to the previous menu")
    print("'save': saves the results from the previous query")
    print("'count': prints the number of results returned by the previous query")
    print("'results': view the previous set of results")
    print("'all': load all available data as the current result set")
    print('%s\n' % DIVIDER)

    context = InteractionContext(data)
    while not context.quit:
        response, context = handle_input('What information are you interested in?', 'Your current query options are: port, ip, os, and device', context)

        if context.return_to_previous:
            print("\nCannot go back; there is nowhere to return to\n")
            context.return_to_previous = False
            continue

        # Do not continue to attempt to handle user input if they just typed 'quit'
        if context.quit:
            break

        if response in ('port', 'ports'):
            context = handle_port_query(context)
        elif response == 'ip':
            context = handle_ip_query(context)
        elif response == 'os':
            context = handle_os_query(context)
        elif response == 'device':
            context = handle_device_query(context)
        elif response == 'all':
            context.results = context.scan_data
        else:
            print("\nUnknown command '%s' entered; please try again\n" % response)

def filter_data(data, ports_filter, ips_filter, os_filter, device_type_filter):
    filtered_data = data

    if ports_filter:
        filtered_data = data.query_by_port(ports_filter)

    if ips_filter:
        filtered_data = data.query_by_ip(ips_filter)

    if os_filter:
        filtered_data = data.query_by_os_prefix(os_filter)

    if device_type_filter:
        filtered_data = data.query_by_device_prefix(device_type_filter)

    return filtered_data    

def main(argv):
    short_options = [prep_short_option(definition) for definition in OPTIONS_DEFINITIONS]
    long_options = [prep_long_option(definition) for definition in OPTIONS_DEFINITIONS]

    try:
        opts, args = getopt.getopt(argv, "".join(short_options), long_options)
    except getopt.GetoptError:
        print_usage_and_exit(2)

    input_file = None # Default to reading the scan results from STDIN
    output_file = None # Default to writing output to STDOUT

    # Default to including all data which is not expictly filtered out
    ports_filter = None
    ips_filter = None
    os_filter = None
    device_type_filter = None
    
    output_format = 'default'
    query_mode = False # Indicates whether or not the user wants to perform interactive queries (defaults to false)

    if len(opts) == 0:
        print_usage_and_exit(0)
        
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print_usage_and_exit(0)
        elif opt in ('-i', '--input-file'):
            if not os.path.isfile(arg):
                print("\nInvalid input file '%s'; file does not exist\n" % arg)
                sys.exit(1)
                
            input_file = arg
        elif opt in ('-o', '--output-file'):
            output_file = arg
        elif opt in ('-p', '--ports'):
            ports_filter = parse_filter_string(arg)
        elif opt in ('-a', '--ip-addrs'):
            ips_filter = parse_filter_string(arg)
        elif opt in ('-os', '--operating-system'):
            os_filter = parse_filter_string(arg)
        elif opt in ('-d', '--device-type'):
            device_type_filter = parse_filter_string(arg)
        elif opt in ('-c', '--output-csv'):
            output_format = 'csv'
        elif opt in ('-q', '--query-mode'):
            query_mode = True
        else:
            print("\nUnknown option '%s' encountered" % (opt))
            print_usage_and_exit(0)

    if query_mode and (ports_filter != None or ips_filter != None or output_file != None):
        print("\nError: can only use the -i / --input-file option when running in query mode (-q / --query-mode)\n")
        sys.exit(2)

    if input_file == None:
        if query_mode:
            print("Reading data from STDIN...\n")
            
        data = ScanData.create_from_nmap_data(sys.stdin)
    else:
        with open(input_file, 'r') as f:
            data = ScanData.create_from_nmap_data(f)

    if query_mode:
        handle_queries(data)
    else:
        data = filter_data(data, ports_filter, ips_filter, os_filter, device_type_filter)
        
        if output_file != None:
            data.save(output_file, output_format)
        else:
            data.print_data()

# If this file is being run as the "main" file / script,
# call the main() function
if __name__ == "__main__":
    main(sys.argv[1:])
