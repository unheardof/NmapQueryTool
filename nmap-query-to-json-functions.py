class HostData:
    def to_json(self):
        # TODO: Implement
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

class ScanData:
    def to_json(self):
        lines = []
        for ip in self.host_data_by_ip:
            lines.append(str(self.host_data_by_ip[ip]))
            
        return '\n'.join(lines)

class PortData:
    def to_json(self):
        tokens = [self.port_number]
        tokens.append(value_as_str(self.protocol))
        tokens.append(value_as_str(self.state))
        tokens.append(value_as_str(self.service))
        tokens.append(value_as_str(self.version))

        return ' '.join(tokens)
