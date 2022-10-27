import secrets
import time

from .common import *
from nexus.constants import PERM_DENY
from nexus.domain.auth import TrieNode
from nexus.log import log

##################################################
# NexusCookie instance
##################################################

YAML_TEMPLATE_COOKIE = NexusSchema.from_yaml("""
version: 1

created:
  help: |-
    Timestamp when the cookie was created
  default:

max_age:
  help: |-
    maximum lifetime of the tracking/authenticating cookie
    this will be compared against the file's mtime and if
    it's out of date, it will be removed
  default:

modified:
  help: |-
    UTC timestamp when the cookie was modified
  default:

authid:
  help: |-
    when a cookie has been set, and the WAMP session
    was successfully authenticated thereafter, the latter
    auth info is store here
  default:

authrole:
  help: |
  default:

authrealm:
  help: |
  default:

authmethod:
  help: |
  default:

authextra:
  help: |
  default:

connections:
  help: |-
    set of WAMP transports (WebSocket connections) this
    cookie is currently used on
  default:

data:
  help: |-
    Session data
  default:

""")



class NexusCookie(NexusRecord):
    """ Handles a single Nexus Cookie
    """
    _schema = YAML_TEMPLATE_COOKIE
    _trie = None

    def cbt_data(self):
        data = self.dict_()
        data['connections'] = set(data['connections'] or [])
        return data

    def expired_(self):
        """ Returns a true value if the record has gone stale
        """
        age = time.time() - self.mtime_()
        return age > self.max_age

    def touch_(self):
        super().touch_()

    def uri_authorizer_(self, force=False):
        restrictions = self.data.get('restrictions')
        if not restrictions:
            return

        if force or not self._trie:
            self._trie = TrieNode()
            for perm in restrictions:
                self._trie.append(perm['uri'], str_perms(perm['perms']))
        return self._trie

    def authorize_(self, uri, action ):
        """ Figure out based upon the list of available uri permissions if
            this role is allowed to run the particular action
        """
        perms = self.uri_authorizer_().match(uri)
        if not perms:
            return PERM_DENY
        permission = perms.data.get(action) or PERM_DENY
        return permission

    @property
    def last_authentication_age(self):
        """ Returns the last time the session was authenticated
        """
        return time.time() - self.data.get('last_authentication',0)

    def touch_reauthenticate(self, time_value=None):
        """ Resets the last_authentication status on the session
        """
        if time_value is not None:
            self.data['last_authentication'] = time_value
        else:
            self.data['last_authentication'] = time.time()
        self.save_()


class NexusCookies(_AuthorizedNexusCollection):
    def create_(self, data_rec, key_length=24):
        """ This creates a new cookie token with id
        """
        # Find a unique key. It's very unlikely we'll have a
        # collision but test and address it, just in case
        while True:
            key = secrets.token_urlsafe(key_length)
            if not self.exists_(key):
                data_rec['key'] = key
                break

        data_rec.setdefault('data',{})\
                .setdefault('last_authentication', 0)

        return self.instantiate_(data_rec)

    def vacuum_(self):
        """ This should be run periodically (probably will be done via cron)
            to remove old and stale cookies from the database
        """

        for c in self:
            if c.expired_():
                c.delete_()
