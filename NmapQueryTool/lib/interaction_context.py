import os

from .nmap_data import NmapData

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
            print('\n%s' % NmapData.DIVIDER)
            print('Results')
            print('%s\n\n' % NmapData.DIVIDER)
            print(self.results)

    @staticmethod
    def write_to_file(filename, content):
        with open(filename, 'w') as f:
            f.write(content)

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
                        self.write_to_file(filename, str(self.results))
                        break
                    else:
                        continue
                else:
                    self.write_to_file(filename, str(self.results))
                    break
