from .common import *

from nexus.log import log

##################################################
# NexusURI
##################################################

YAML_TEMPLATE_URI = """
# Database version. This key should always be present
version: 1

# Database Universal Unique Record ID
uuid: null

# What is the URI?
uri: null

# The URI is connected to what action? Can be one of
#    "register", "publish", "call", "subscribe"
action: null

# Is this URI currently active on the system?
active: false

# System component?
system: false

# URI matching policy. can be one of
#     "exact", "prefix", "wildcard"
match: "exact"

# Invocation rule.
invoke: null

# Description of the purpose of this uri with this action
description: ""

# Contact person or owner of the URI
contact: null

# When this was last registered
create: null

# From where was the last connected entry?
peer: null

# The authid of the last connected creator
authid: null

""".strip()

class NexusURI(NexusRecord):
    _yaml_template = YAML_TEMPLATE_URI
    _key_name = 'key'
    path_format_ = '{parent_path}/{key}/data.yaml'
    ownership_path_format_ = '{parent_path}/{key}/'

    def documented(self):
        # We return True if the owner and description have been defined 
        # This is kind of a simplistic solution for now but for now,
        # it doesn't need to be super clever
        return self.contact and self.description

class NexusURIs(_AuthorizedNexusCollection):
    _record_class = NexusURI
    _role_permissions = {
        'trust': True,
        'trusted': True,
        '%default': False,
    }

    def generate_key_(self, action, match, uri):
        """ Returns the encoded key for the URI that considers:

            - action
            - match scheme
            - uri

            Basically this creates a 
        """
        return '_'.join([uri, match, action])

    def upsert_(self, action, match, uri, data):
        """ Amends records in the database for URI documentation
        """
        uri_key = self.generate_key_(action, match, uri)

        # Record does exist, let's amend it
        rec = self.get_(uri_key)
        if rec:
            for k, v in data.items():
                setattr(rec, k, v)
            rec.save_()

        # No record exists, let's create it
        else:
            new_rec = {
                'key': uri_key,
                'uri': uri,
                'action': action,
            }
            for k, v in data.items():
                if k not in new_rec:
                    new_rec[k] = v
            rec = self.create_(new_rec)

        return rec


