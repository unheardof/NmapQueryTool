from .nmap_data import NmapData

class HostData(NmapData):

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
        lines.append(self.DIVIDER)
        lines.append('')

        return '\n'.join(lines)

    def as_dict(self):
        d = {}
        d['ip'] = self.ip
        d['hostname'] = self.hostname
        d['os_list'] = self.os_list
        d['device_types'] = self.device_types

        for key in self.additional_service_info:
            d[key] = self.additional_service_info[key]

        serialized_port_data = {}
        for port_number in self.data_by_port_number:
            serialized_port_data[self.value_as_str(port_number)] = self.data_by_port_number[port_number].as_dict()

        d['port_data'] = serialized_port_data

        return d

    # Will return a list of dictionaries, with each dictionary containing
    # all of the data for a single row / record in the ultimate output report
    def to_list_of_records(self):
        records = []
        base_dict = {}

        base_dict['IP'] = self.value_as_str(self.ip)
        base_dict['HOSTNAME'] = self.value_as_str(self.hostname)
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
        for port in self.data_by_port_number:
            # Create a copy of the base_dict to prevent editing that dictionary directly
            data_dict = base_dict.copy()
            port_data = self.data_by_port_number[port]

            data_dict['PORT NUMBER'] = self.value_as_str(port_data.port_number)
            data_dict['PROTOCOL'] = self.value_as_str(port_data.protocol)
            data_dict['STATE'] = self.value_as_str(port_data.state)
            data_dict['SERVICE'] = self.value_as_str(port_data.service)

            # Escape any comma's in the service version
            data_dict['VERSION'] = self.value_as_str(port_data.version.replace(',', ''))

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
        if os_data is None:
            print("WARNING: OS data is empty")
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

    def filter_by_port(self, port_numbers, state = None):
        filtered_host_data = self.clone()

        match_found = False
        new_data_by_port_number = {}
        for port in self.data_by_port_number:
            if port in port_numbers:
                port_data = self.data_by_port_number[port]

                # Ignore port state unless one is provided to filter on
                if state is None or port_data.state == state:
                    match_found = True
                    new_data_by_port_number[port] = port_data.clone()

        filtered_host_data.data_by_port_number = new_data_by_port_number

        if match_found:
            return filtered_host_data
        else:
            return None

    def os_is_any_of(self, os_list):
        match_found = False
        for os in self.os_list:
            if self.any_substring_matches(os, os_list):
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
