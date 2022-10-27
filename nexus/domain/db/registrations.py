from .common import *

##################################################
# NexusRegistration
##################################################

YAML_TEMPLATE_URI_REGISTRATION = NexusSchema.from_yaml("""
version: 1

uri:
  help: |-
    What is the URI?
  default:

active:
  help: |-
    Is this URI currently active on the system?
  default: false

system:
  help: |-
    System component?
  default: false

match:
  help: |-
    URI matching policy. can be one of
    "exact", "prefix", "wildcard"
  default: exact

invoke:
  help: |-
    Invocation rule.
  default:

description:
  help: |-
    Description of the purpose of this registration call
  default: ''

owner:
  help: |-
    Owner of the URI
  default:

create:
  help: |-
    When this was last registered
  default:

peer:
  help: |-
    From where was the last connected entry?
  default:

authid:
  help: |-
    The authid of the last connected creator
  default:

""")


class NexusRegistration(NexusRecord):
    _schema = YAML_TEMPLATE_URI_REGISTRATION
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

