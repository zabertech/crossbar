from nexus.log import log

from nexus.orm.common import *

class NexusField:
    def __init__(self, help='', type=None, default=None, ):
        self.help = help.strip()
        self.default = default
        self.type = type

        # This gets set later
        self.name = None

    def convert(self, value):
        """ Returns the value provided in to the data type we expect
        """
        if value is None:
            return

        if not self.type:
            return value

        elif self.type == 'int':
            if value == '':
                return
            return int(value)

        elif self.type == 'float':
            if value == '':
                return
            return int(float)

        log.warn(f"Do not know how to handle type {self.type} ")
        return value
