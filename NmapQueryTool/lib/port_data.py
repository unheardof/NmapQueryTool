from .nmap_data import NmapData

class PortData(NmapData):
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
        tokens = [str(self.port_number)]
        tokens.append(self.value_as_str(self.protocol))
        tokens.append(self.value_as_str(self.state))
        tokens.append(self.value_as_str(self.service))
        tokens.append(self.value_as_str(self.version))

        return ' '.join(tokens)

    def as_dict(self):
        d = {}
        d['port_number'] = self.value_as_str(self.port_number)
        d['protocol'] = self.value_as_str(self.protocol)
        d['state'] = self.value_as_str(self.state)
        d['service'] = self.value_as_str(self.service)
        d['version'] = self.value_as_str(self.version)

        return d

    def clone(self):
        new_port_data = PortData(self.port_number, self.protocol)
        new_port_data.state = self.state
        new_port_data.service = self.service
        new_port_data.version = self.version

        return new_port_data
