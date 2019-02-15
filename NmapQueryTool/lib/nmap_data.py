
class NmapData:
    DIVIDER = '--------------------------------------------------------------------------------'

    @staticmethod
    def any_prefix_matches(string, prefixes):
        for prefix in prefixes:
            if string.startswith(prefix):
                return True

        return False

    @staticmethod
    def any_substring_matches(string, substrings):
        for substring in substrings:
            if substring in string:
                return True

        return False

    @staticmethod
    def value_as_str(value):
        if value == None:
            value = ''

        return str(value)

