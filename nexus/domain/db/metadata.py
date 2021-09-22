from .common import *
from nexus.orm.common import yaml_dumps, yaml_loads

##################################################
# Nexus Metadata Objext
##################################################

YAML_TEMPLATE_METADATA = """
# Database version. This key should always be present
version: 1

# Database Universal Unique Record ID
uuid: null

# The data structure representing the preference information. We don't use it in the system
# so the structure itself can be as simple as a string or as complex as a series of nested
# dicts and lists
value: null
""".strip()

class NexusMetadatum(NexusRecord):
    _yaml_template = YAML_TEMPLATE_METADATA
    _key_name = 'key'

    def dict_(self, yaml=False):
        if not yaml:
            return super().dict_(yaml)
        rec = {
            'key': self.key,
            'uuid': self.uuid,
            'value': self.value_yaml,
        }
        return rec

    def get_item_(self,k):
        if k == 'value_yaml':
            return yaml_dumps(self.value)
        return super().get_item_(k)

    def set_item_(self,k,v):
        if k == 'value_yaml':
            v = yaml_loads(v)
            k = 'value'
        super().set_item_(k,v)

class NexusMetadata(_AuthorizedNexusCollection):
    _record_class = NexusMetadatum
    _role_permissions = {
        'trust': True,
        '%default': {
            'query':  authorize_owned_query('owner'),
            'update': authorize_owned_update('owner'),
            'create': authorize_owned_create('uuid'),
            'delete': authorize_owned_delete('owner'),
        }
    }
