import secrets
import time

from .common import *

from izaber import config

from nexus.constants import PERM_DENY, PERM_ALLOW
from nexus.domain.auth import TrieNode
from nexus.log import log

##################################################
# NexusCookie instance
##################################################

YAML_TEMPLATE_COOKIE = NexusSchema.from_yaml("""
version: 2

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

expires:
  help: |-
    When this cookie expires. This means that even if the user
    refreshes the cookie periodically, this cookie will expire
    after a certain amount of time. Blank if this does not have
    any impact
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
        """ Returns the validity status of the key. There are two places
            that we need to test.
            1. The age of this cookie, since it's past a certain age
               we deem it expired
            2. If the cookie, even if it's fresh, we will mark it dead when
               the cookie's expires timestamp is passed
        """

        # Do we pass the absolute limit on this cookie's lifetime?
        if self.expires:
            return timestamp_passed(self.expires)

        # Check the age of of last use
        age = time.time() - self.mtime_()
        return age > self.max_age

    def touch_(self, lazy_refresh=False):
        """ Touches the cookie file to denote that it's still active.
            The lazy_refresh argument will allow us to touch the file
            only when it's alive so that we don't keep hammering it
        """
        if lazy_refresh:
            age = time.time() - self.mtime_()
            if age > self.max_age / 2:
                super().touch_()
        else:
            super().touch_()

    def auth_scheme_(self):
        """ Returns what method was used to authenticate the user
        """
        if auth := self.data.get('auth',[]):
            return auth[0]
        return

    def uri_authorizer_(self, force=False):
        """ Generates an Trie authorizer based upon the current session's
            restrictions. If there are not restrictions at all, we'll just
            return None
        """
        if force or not self._trie:

            # We may need to add some default restrictions based upon which
            # authentication scheme is being used
            auth_scheme = self.auth_scheme_()
            default_restrictions = config.nexus.get(auth_scheme,{}).get('permissions',[])

            # The session specific restrictions
            restrictions = self.data.get('restrictions', [])

            # If there are no restrictions present, we'll just drop out
            if not ( restrictions or default_restrictions ):
                return

            if force or not self._trie:
                self._trie = TrieNode()
                if not restrictions:
                    restrictions.append(dict(
                        uri="*",
                        perms="crspoq"
                    ))
                for perm in restrictions:
                    self._trie.append(perm['uri'], str_perms(perm['perms']))

                for perm in default_restrictions:
                    try:
                        self._trie.append(perm['uri'], str_perms(perm['perms']))
                    except PatternAlreadyExists:
                        pass

        return self._trie

    def authorize_(self, uri, action ):
        """ Figure out based upon the list of available uri permissions if
            this role is allowed to run the particular action
        """
        authorizer = self.uri_authorizer_()
        if not authorizer:
            return PERM_ALLOW
        perms = authorizer.match(uri)
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

