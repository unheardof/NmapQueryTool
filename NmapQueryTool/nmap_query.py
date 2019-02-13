#!/usr/bin/env python3

import sys, getopt, os, csv

from lib.host_data import HostData
from lib.nmap_data import NmapData
from lib.port_data import PortData
from lib.scan_data import ScanData
from lib.interaction_context import InteractionContext

# Note: this script is Python 3.6 compatible only (i.e. no Python 2.7 support)

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
            'short': 's',
            'long': 'operating-system',
            'value_name': 'OS',
            'usage_msg': '[-s | --operating-system] OS: specify one or more operating systems on which to filter. The following input formats are accepted:\n\n\tSingle operating system: -s Windws\n\tSet of operating systems: -s Windows,Linux\n'

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
    lines.append("Usage: python nmap_query.py %s" % (" ".join(options)))
    lines.append("")
    lines.append("\tNote: the nmap scan results can be provided either through an input file or from STDIN (through a pipe)")
    lines.append("")
    lines.append("\tExample: nmap -sV 10.0.0.0/24 | python nmap_query.py -q")
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
        elif response == 'clear':
            os.system('clear')
        else:
            break

    return response, context

# TODO: Ensure the provided filter string is valid
def parse_filter_string(str):
    # Allow "22,33,44" and "22, 33, 44" (and "22,33, 44")
    return [s.strip() for s in str.split(',')]

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
    context.results = context.results.query_by_port(ports)
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
    context.results = context.results.query_by_ip(ips)
    context.print_results()

    return context    

def handle_os_query(context):
    response, context = handle_input(OS_QUERY_PROMPT_MSG, OS_QUERY_HELP_MSG, context)

    if context.quit or context.return_to_previous:
        context.return_to_previous = False
        return context

    target_operating_systems = parse_filter_string(response)
    context.results = context.results.query_by_os(target_operating_systems)
    context.print_results()

    return context

def handle_device_query(context):
    response, context = handle_input(DEVICE_QUERY_PROMPT_MSG, DEVICE_QUERY_HELP_MSG, context)

    if context.quit or context.return_to_previous:
        context.return_to_previous = False
        return context

    target_device_prefixes = parse_filter_string(response)
    context.results = context.results.query_by_device_prefix(target_device_prefixes)
    context.print_results()

    return context

def handle_queries(data):
    print('\n%s' % NmapData.DIVIDER)
    print("Entering query mode\n")
    print("The following commands can be used at any time:\n")
    print("'quit': exits the program")
    print("'help': gets help")
    print("'back' or 'previous': go back to the previous menu")
    print("'save': saves the results from the previous query")
    print("'count': prints the number of results returned by the previous query")
    print("'results': view the previous set of results")
    print("'reset': load all available data as the current result set")
    print('%s\n' % NmapData.DIVIDER)

    context = InteractionContext(data)

    while not context.quit:
        # TODO: Add list of general control commands (help, count, results, quit, etc.) as well
        # TODO: Make list of commands dynamic instead of static
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
        elif response == 'reset':
            context.results = context.scan_data
        else:
            print("\nUnknown command '%s' entered; please try again\n" % response)

def filter_data(data, ports_filter, ips_filter, os_filter, device_type_filter):
    filtered_data = data

    if ports_filter:
        filtered_data = filtered_data.query_by_port(ports_filter)

    if ips_filter:
        filtered_data = filtered_data.query_by_ip(ips_filter)

    if os_filter:
        filtered_data = filtered_data.query_by_os(os_filter)

    if device_type_filter:
        filtered_data = filtered_data.query_by_device_prefix(device_type_filter)

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
        elif opt in ('-s', '--operating-system'):
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

    if sys.stdin.isatty() and input_file is None:
        print("\nMust provide input file when not providing data via a pipe\n")
        print_usage_and_exit(0)

    if query_mode and (ports_filter != None or ips_filter != None or os_filter != None or output_file != None):
        print("\nError: can only use the -i / --input-file option when running in query mode (-q / --query-mode)\n")
        sys.exit(2)

    if input_file == None:
        if query_mode:
            print("Error: cannot use interactive query mode when reading input from STDIN; please use the -i <INPUT FILE> option when -q is provided")
            sys.exit(1)
            
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
