import secrets
import time

from .common import *
from nexus.constants import PERM_DENY
from nexus.domain.auth import TrieNode
from nexus.log import log

##################################################
# NexusRoster instance
##################################################

YAML_TEMPLATE_ROSTER = NexusSchema.from_yaml("""
version: 1

created:
  help: |-
    Timestamp when the roster entry was created
  default:

name:
  help: |-
    Roster Name
  default:

visibility:
  help: |-
    Who can see this
    A list of all roles that are allowed to view the entries
    For many purposes it may be best to use ['frontend','backend']
    Trust level access can see all entries
  default: []

session_id:
  help: |-
    The session that owns this roster entry
  default:

data:
  help: |-
    Roster data
  default:

""")


class NexusRoster(NexusRecord):
    """ Handles a single Nexus Roster
    """
    _schema = YAML_TEMPLATE_ROSTER
    _key_name = 'key'

class NexusRosters(_AuthorizedNexusCollection):

    def generate_key_(self, session_id, roster_name):
        """ Returns the encoded key for the Roster Entry
        """
        return f"{session_id}_{roster_name}"

    def register_(self, session_id, roster_name, roster_data):
        """ Amends roster entries
        """
        roster_key = self.generate_key_(session_id, roster_name)

        # Record does exist, let's amend it
        rec = self.get_(roster_key)
        if rec:
            for k in ['visbility','data']:
                if k in roster_data:
                    rec[k] = roster_data[k]
            rec.save_()

        # No record exists, let's create it
        else:
            new_rec = {
                'session_id': session_id,
                'name': roster_name,
                'created': time.time(),
                'key': roster_key,
                'visibility': '*',
            }
            for k in ['visibility','data']:
                if k in roster_data:
                    new_rec[k] = roster_data[k]
            rec = self.create_(new_rec)

        return rec

    def unregister_(self, session_id, roster_name):
        roster_key = self.generate_key_(session_id, roster_name)
        rec = self.get_(roster_key)
        if not rec:
            return

        rec.delete_()
        return True
