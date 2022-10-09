__all__ = [
  '_AuthorizedNexusCollection',
  'NexusRecord',
  'NexusSchema',
  'NexusField',
  'authorize_owned_query',
  'authorize_owned_update',
  'authorize_owned_create',
  'authorize_owned_delete',
  'perm_allow',
  'perms_str',
  'str_perms',
]

import re

from nexus.constants import PERM_DENY, PERM_REQUIRE_ELEVATED, PERM_ALLOW, \
                            PERM_REQUIRE_DOCUMENTATION, \
                            PERMS, TRAIT_TO_CODE, PERM_REGEX, PERM_TO_CODE, PERM_TO_NAME, \
                            TRAITS, TRAIT_TO_NAME
from nexus.orm import NexusRecord, NexusCollection, NexusField, NexusSchema

class Perm:
    perm_code = None
    perm_val = None
    traits = None

    def __init__(self, perm_code, perm_val=PERM_DENY, traits_str=None):
        self.perm_code = perm_code
        self.perm_val  = perm_val
        self.traits = {}.fromkeys(TRAIT_TO_CODE.keys(), False)
        self.traits_parse(traits_str)

    def traits_parse(self, traits_str):
        """ Takes a string similar to "+", or "!+" and extracts the associated
            metadata.
        """
        if not traits_str:
            return

        for trait_code in traits_str:
            if trait_code not in TRAIT_TO_NAME:
                continue
            trait_name = TRAIT_TO_NAME[trait_code]
            self.traits[trait_name] = True

    def __bool__(self):
        return bool(self.perm_val)

    def __eq__(self, other):
        if other == PERM_ALLOW:
            return self.perm_val == PERM_ALLOW

        if other == PERM_DENY:
            return self.perm_val == PERM_DENY

        if other == PERM_REQUIRE_ELEVATED:
            return self.require_elevated

        if other == PERM_REQUIRE_DOCUMENTATION:
            return self.require_documentation

    def __str__(self):
        if not self.perm_val:
            return ''

        s = self.perm_code
        for trait_name, trait_code in TRAITS:
            if not self[trait_name]: continue
            s += trait_code

        return s

    def __getitem__(self, k):
        return self.traits[k]
    __getattr__ = __getitem__

    def __setitem__(self, k, v):
        if self.traits and k in self.traits:
            self.traits[k] = v
        else:
            object.__setattr__(self, k, v)
    __setattr__ = __setitem__


class _AuthorizedNexusCollection(NexusCollection):
    _role_permissions = {
        'trust': True,
        'trusted': True,
        '%default': False,
    }

    @classmethod
    def authorize(cls, db, login, action, **kwargs ):
        user_obj = db.users[login]
        role = user_obj.role

        rule = cls._role_permissions.get(role) \
                or cls._role_permissions.get('%default')

        if rule is None:
            raise PermissionError(f"{repr(role)} denied {action} access")

        # If we use a boolean for a role, we treat it as a short hand for
        # all actions
        if isinstance(rule, bool):
            if rule:
                return kwargs
            raise PermissionError(f"{role} denied {action} access")

        # The rule is a dict. Then there should be a boolean or a
        # function/lambda to calculate or modify the arguments if needed
        action_rule = rule.get(action, False)
        if isinstance(action_rule, bool):
            if action_rule:
                return kwargs
            raise PermissionError(f"{role} denied {action} access")

        # Run the custom code to authorize and if required modify
        # the permissions
        try:
            return action_rule(cls, db, user_obj, action, kwargs)
        except PermissionError as ex:
            raise
        except Exception as ex:
            msg = f"{cls.__name__}.{role}.{action_rule.__name__}:{ex}"
            log.error(msg)
            raise RuntimeError(msg)

##################################################
# Authorization ownership when parent record owns
##################################################

def authorize_owned_query(owner='owner'):
    def _authorize_owned_query(cls, db, user_obj, action, kwargs):
        new_conditions = [[owner,'=',user_obj.uuid]]
        if kwargs['conditions']:
            new_conditions.extend(kwargs['conditions'])
        kwargs['conditions'] = [['AND',new_conditions]]

        return kwargs
    return _authorize_owned_query

def authorize_owned_update(owner='owner',remove_fields=[],allow_fields=[]):
    def _authorize_owned_update(cls, db, user_obj, action, kwargs):
        """ Amend the search so it only returns entries that the user is
            allowed to see (themselves) along with only the fields that
            they are allowed to modify
        """

        # Each uid_b64 should be referring to a NexusAPIKey record
        # so we should be abel to get some information like so:
        uid_b64s = []
        for uid_b64 in kwargs['uid_b64s']:
            record = db.get(uid_b64)
            if record[owner] != user_obj.uuid:
                continue
            uid_b64s.append(uid_b64) 
        kwargs['uid_b64s'] = uid_b64s

        # And remove any sensitive fields
        data_rec = kwargs['data_rec']
        for k in remove_fields+['uuid','version']:
            if k in data_rec:
                del data_rec[k]

        # If we're only allowing certain fields to be updated
        if allow_fields:
            new_data_rec = {}
            for k in allow_fields:
                if k in data_rec:
                  new_data_rec[k] = data_rec[k]
            kwargs['data_rec'] = new_data_rec

        return kwargs
    return _authorize_owned_update

def authorize_owned_create(owner='uuid',remove_fields=[],allow_fields=[]):
    def _authorize_owned_create(cls, db, user_obj, action, kwargs):
        parent_uid_b64 = kwargs['parent_uid_b64']
        if not parent_uid_b64:
            raise ValueError('No parent UUID provided')
        parent_rec = db.get(parent_uid_b64)
        if not parent_rec:
            raise ValueError('No parent UUID not matched')
        if not parent_rec['uuid'] == user_obj.uuid:
            raise PermissionError(f"Not allowed add to this parent record")

        # And remove any sensitive fields
        data_rec = kwargs['data_rec']
        for k in remove_fields+['uuid','version']:
            if k in data_rec:
                del data_rec[k]

        # If we're only allowing certain fields to be updated
        if allow_fields:
            new_data_rec = {}
            for k in allow_fields:
                if k in data_rec:
                  new_data_rec[k] = data_rec[k]
            kwargs['data_rec'] = new_data_rec

        return kwargs
    return _authorize_owned_create

def authorize_owned_delete(owner='owner'):
    def _authorize_owned_delete(cls, db, user_obj, action, kwargs):
        """ Amend the search so it only returns entries that the user is
            allowed to delete (themselves)
        """
        # Each uid_b64 should be referring to a NexusAPIKey record
        # so we should be abel to get some information like so:
        for uid_b64 in kwargs['uid_b64s']:
            record = db.get(uid_b64)
            if record[owner] != user_obj.uuid:
                raise PermissionError(f"{user_obj.login} does not own record {repr(uid_b64)}")
        return kwargs
    return _authorize_owned_delete


def perm_allow(perm_name):
    # This creates a permission object that just allows access
    if perm_name not in PERM_TO_CODE:
          raise ValueError(f"Unknown Permission {perm_name}")
    return Perm(PERM_TO_CODE[perm_name], PERM_ALLOW)

##################################################
# Permission string parsers
##################################################

def perms_str(perm,blank='-'):
# --------------------------------------------------
# Permissions should be of the type:
# - : spacer
# X : where X is a permission type of c, r, s, p
#     if the value is on its own, it represents PERM_ALLOW
#     if structured like the following:
# X+ : this implies that accessing X is allowed but requires
#      elevated permissions to do so
#
    p = ''
    for perm_name, perm_code  in PERMS:
        p += str(perm[perm_name])
    return p

def str_perms(perms):
# --------------------------------------------------
# Permissions should be of the type:
# - : spacer
# X : where X is a permission type of c, r, s, p
#     if the value is on its own, it represents PERM_ALLOW
#     if structured like the following:
# X+ : this implies that accessing X is allowed but requires
#      elevated permissions to do so
# r! : Any registration that matches requires an entry in the 
#      uris table
#
    perm_struct = {}
    for perm_name, perm_code in PERMS:
        perm_struct[perm_name] = Perm(perm_code)

    if not perms:
        return perm_struct

    for perm_code, modifier in  re.findall( PERM_REGEX, perms ):
        perm_name = PERM_TO_NAME[perm_code]
        perm_struct[perm_name] = Perm(perm_code, PERM_ALLOW, modifier)

    return perm_struct
