from .common import *

##################################################
# NexusRegistration
##################################################

YAML_TEMPLATE_URI_REGISTRATION = """
# Database version. This key should always be present
version: 1

# Database Universal Unique Record ID
uuid: null

# What is the URI?
uri: null

# Is this URI currently active on the system?
active: false

# System component?
system: false

# URI matching policy. can be one of
#     "exact", "prefix", "wildcard"
match: "exact"

# Invocation rule.
invoke: null

# Description of the purpose of this registration call
description: ""

# Owner of the URI
owner: null

# When this was last registered
create: null

# From where was the last connected entry?
peer: null

# The authid of the last connected creator
authid: null

""".strip()

class NexusRegistration(NexusRecord):
    _yaml_template = YAML_TEMPLATE_URI_REGISTRATION
    _key_name = 'key'
    path_format_ = '{parent_path}/{key}/data.yaml'
    ownership_path_format_ = '{parent_path}/{key}/'

    def documented(self):
        # We return True if the owner and description have been defined 
        # This is kind of a simplistic solution for now but for now,
        # it doesn't need to be super clever
        return self.owner and self.description

class NexusRegistrations(_AuthorizedNexusCollection):
    _record_class = NexusRegistration

