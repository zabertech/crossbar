from nexus.constants import LOCAL_UPN_DOMAIN, AUTH_SOURCE_LOCAL

import shutil
import passlib

from .common import *
from .apikeys import NexusAPIKeys
from .metadata import NexusMetadata

##################################################
# Nexus User Objext
##################################################

YAML_TEMPLATE_USER = """
# Database version. This key should always be present
version: 1

# Database Universal Unique Record ID
uuid: null

# Is the user allowed to access the bus? Note that if the
# setting is enabled yet the user is unable to authenticate from
# LDAP, the user will not be permitted to use the bus
enabled: True

# What role should be assigned to the user upon login
# by default we have been using "frontend". Can also be "backend"
# or "trust"
role: null

# What is the principle source of user metadata. Can be "ldap" to
# test against the ldap source or "local" for internal database
# This does not have any impact on keys which must be local regardless
source: "local"

# If the source is local, the hashed password is defined here. The passwords
# can be generated with:
# import passlib.hash; print(passlib.hash.pbkdf2_sha256("password"))
password: null

# If the source is local, email address of the entity
email: null

# If the source is local, the userPrincipalName
upn: null

# If the source is local, the user's name
name: null
""".strip()

class NexusUser(NexusRecord):
    _yaml_template = YAML_TEMPLATE_USER
    path_format_ = '{parent_path}/{key}/data.yaml'
    ownership_path_format_ = '{parent_path}/{key}/'

    _collections = {
        'apikeys': NexusAPIKeys,
        'metadata': NexusMetadata,
    }

    _key_name = 'login'

    def init_(self):
        """ Force the UPN if not set
        """
        if not self.upn:
            self.upn = f"{self.login}@{LOCAL_UPN_DOMAIN}"

    def dict_(self, yaml=False, shallow=False):
        user_rec = super().dict_(yaml)
        if not user_rec: return

        if not shallow:
            user_rec['apikeys'] = self.apikeys.list_(yaml)
            user_rec['metadata'] = self.metadata.list_(yaml)

        return user_rec

    def authenticate(self, password):
        """ Returns a true value if the user is internal and the
            password hash matches
        """
        if self.source != AUTH_SOURCE_LOCAL:
            return False
        return passlib.hash.pbkdf2_sha256.verify(password, self.password)

    def set_item_(self, k, v):
        """ If the key is plaintext password, it's not the hashed
            value so we'll calculate it for the user
        """
        if k == 'plaintext_password':
            v = passlib.hash.pbkdf2_sha256.hash(v)
            k = 'password'
        super().set_item_(k, v)


class NexusUsers(_AuthorizedNexusCollection):
    _role_permissions = {
        'trust': True,
        '%default': {
            'query':  authorize_owned_query('uuid'),
            'update': authorize_owned_update('uuid',
                          allow_fields=['password','email','name']),
            'create': False,
            'delete': False,
        }
    }

