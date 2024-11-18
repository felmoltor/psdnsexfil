
class Base36():
    # Code extracted from https://stackoverflow.com/questions/1181919/python-base-36-encoding
    @staticmethod
    def encode(decimal=None, alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
        """Converts an integer to a base36 string."""
        if (decimal is not None and not isinstance(decimal, (int))):
            raise TypeError('number must be an integer')

        base36 = ''
        sign = ''
        if decimal < 0:
            sign = '-'
            decimal = -decimal
        if 0 <= decimal < len(alphabet):
            return sign + alphabet[decimal]
        while decimal != 0:
            decimal, i = divmod(decimal, len(alphabet))
            base36 = alphabet[i] + base36
        return sign + base36

    @staticmethod
    def decode(base36=None, alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
        if (base36 is not None and (False in [c.upper() in alphabet for c in base36])):
            raise TypeError('Base36 number contains an invalid character')
        
        return int(base36, 36)