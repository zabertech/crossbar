from .common import *

from nexus.constants import PERM_DENY, PERM_ALLOW
from nexus.domain.auth import TrieNode

import logging
log = logging.getLogger('nexus-db')

##################################################
# Nexus Role Objext
##################################################

YAML_TEMPLATE_ROLE = """
# Database version. This key should always be present
version: 1

# Database Universal Unique Record ID
uuid: null

# Permissions should be structured as a string string
#
# - : spacer
# X : where X is a permission type of c, r, s, p, o, q
#                 c: Allow Calling
#                 r: Allow Registering
#                 s: Allow Subscribing
#                 p: Allow Publishing
#                 o: Allow Roster Registration
#                 q: Allow Roster Querying
#     if the value is on its own, it represents PERM_ALLOW
#     if structured like the following:
# X+ : this implies that accessing X is allowed but requires
#      elevated permissions to do so
# r! : anything registering with this rule MUST have metadata
#      registered in the uris orm
#
# Example of a perms are
#    - c+q
#    - c-s-
#    - cs
#    - r!
#
# If permissions is an empty array, the role has access to nothing: []
permissions: []

""".strip()

class NexusRole(NexusRecord):
    _yaml_template = YAML_TEMPLATE_ROLE
    path_format_ = '{parent_path}/{key}/data.yaml'
    ownership_path_format_ = '{parent_path}/{key}/'
    _trie = None
    _key_name = 'role'

    def uri_authorizer_(self, force=False):
        if force or \
          not self._trie \
          or len(self.permissions) != len(self._trie.rules):
            self._trie = TrieNode()

            # We need to determine if there are any duplicates so
            # first we create a lookup table
            perms_lookup = {}
            for perm in self.permissions:
                uri = perm['uri']
                perms_struct = str_perms(perm['perms'])
                if uri in perms_lookup:
                    log.warning(f"{self.role}.permission duplicate on '{uri}'")
                    old_perms_struct = perms_lookup[uri]
                    for perm_name, modifier in old_perms_struct.items():
                        if perms_struct[perm_name] == modifier:
                            continue
                        else:
                            perms_struct[perm_name] = PERM_DENY
                            log.error(f"{self.role}.permission duplicate on '{uri}'. Mismatch on {perm_name}. DENY_MODE")
                else:
                    perms_lookup[uri] = perms_struct

            for uri, perms_struct in perms_lookup.items():
                self._trie.append(uri, perms_struct)
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

    def vacuum_(self):
        """ This will clean up permissions so that duplicated entries
            get disposed
        """
        permissions = self.permissions.copy()
        self.permissions.clear()
        perms_lookup = {}

        # Build a uri -> [ records ] for finding out
        # which permissions have duplicates
        for perm in permissions:
            uri = perm['uri']
            perms = perm['perms']
            perms_lookup.setdefault(uri,{})[perms] = True

        # Rebuild the index
        for uri, perms in sorted(perms_lookup.items()):
            for perm in perms.keys():
                self.permissions.append({
                  'uri': uri,
                  'perms': perm,
                })

        self.save_()

class NexusRoles(_AuthorizedNexusCollection):

    def init_(self):

        # Then we need to load up the uri authorizer
        self.refresh_uri_authorizer_()

    def refresh_uri_authorizer_(self):
        for role_obj in self:
            role_obj.uri_authorizer_(force=True)

    def uri_permissions_(self, role, uri, action):

        # If the role is a trusted role, we will automatically allow the action
        # however, that user may have disabled the action via their authorization
        # key so we have to validate that still.
        # FIXME: Eventually `trust` should be a part of the role record or managed
        #        with a carte blanche permission set
        if role in ('trust','trusted'):
            return PERM_ALLOW

        elif role not in self:
            return PERM_DENY

        return self[role].authorize_(uri, action)

    def vacuum_(self):
        for role in self:
            role.vacuum_()

