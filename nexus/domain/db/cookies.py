import secrets
import time

from .common import *
from nexus.constants import PERM_DENY
from nexus.domain.auth import TrieNode

##################################################
# NexusCookie instance
##################################################

YAML_TEMPLATE_COOKIE = """
# Database version. This key should always be present
version: 1

# Database Universal Unique Record ID
uuid: null

# UTC timestamp when the cookie was created
created: null

# maximum lifetime of the tracking/authenticating cookie
# this will be compared against the file's mtime and if
# it's out of date, it will be removed
max_age: null

# UTC timestamp when the cookie was modified
modified: null

# when a cookie has been set, and the WAMP session
# was successfully authenticated thereafter, the latter
# auth info is store here
authid: null
authrole: null
authrealm: null
authmethod: null
authextra: null

# set of WAMP transports (WebSocket connections) this
# cookie is currently used on
connections: null

# Session data
data: null

""".strip()


class NexusCookie(NexusRecord):
    """ Handles a single Nexus Cookie
    """
    _yaml_template = YAML_TEMPLATE_COOKIE
    _trie = None

    def cbt_data(self):
        data = self.dict_()
        data['connections'] = set(data['connections'] or [])
        return data

    def expired_(self):
        """ Returns a true value if the record has gone stale
        """
        age = time.time() - self.yaml_fpath_.stat().st_mtime
        print(f"COOKIE AGE   {self.key} {age} > {self.max_age}")
        return age > self.max_age

    def touch_(self):
        super().touch_()
        print(f"COOKIE TOUCH {self.key} {self.mtime_()}")

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
        permission = int(perms.data.get(action) or PERM_DENY)
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

