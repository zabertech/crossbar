import secrets
import passlib
import base64
import pytz


from .common import *

from nexus.domain.auth import TrieNode

##################################################
# NexusOTP instance
##################################################

YAML_TEMPLATE_OTP = NexusSchema.from_yaml("""
version: 1

origin:
  help: |-
    Log information related to the origination of the OTP request for
    the purposes of audit records
  default:

expires:
  help: |-
    When this key expires. Use the ISO date format
  default:

permissions:
  help: |-
    Permissions should be structured as a string string

    - : spacer
    X : where X is a permission type of c, r, s, p
    c: Allow Calling
    r: Allow Registering
    s: Allow Subscribing
    p: Allow Publishing
    if the value is on its own, it represents PERM_ALLOW
    if structured like the following:
    X+ : this implies that accessing X is allowed but requires
    elevated permissions to do so

    Example of a perms are
    - c+
    - c-s-
    - cs

    If there is no limit to the range, simply use permissions: []
  default: []

""")

def generate_secure_hash(login, key):
    """ Creates a hash based upon login as salt and key as
        the plaintext value to hash
    """
    hashed = passlib.hash.pbkdf2_sha256.using(salt=login.encode('utf8')).hash(key)
    hashed = passlib.hash.pbkdf2_sha256.parsehash(hashed)
    hash_str = base64.urlsafe_b64encode(hashed['checksum'])[:-1]
    return hash_str.decode('utf8')

class NexusOTP(NexusRecord):
    """ Handles a single Nexus OTP
    """
    _schema = YAML_TEMPLATE_OTP
    _exclude_keys_dict = ['version', 'key']
    _trie = None
    plaintext_key = None

    def dict_(self, yaml=False, shallow=False):
        rec = super().dict_(yaml)
        rec['plaintext_key'] = self.plaintext_key
        rec['login'] = self.parent_.parent_.login
        return rec

    @property
    def login(self):
        return self.parent_.parent_.login

    @property
    def key(self):
        return self.yaml_fpath_.stem

    def expired(self):
        """ Returns the validity status of the key check expires date and remove
            if it's expired
        """
        # if expiry is null, we delete this OTP
        if not self.expires:
            self.delete_()
            return False
        if timestamp_passed(self.expires):
            self.delete_()
            return True
        else:
            return False

    def effective_role(self):
        """ Returns the current role for the user. The role can be set
            in the api key, the user
        """
        return self.get_('role') \
                or self.parent_.parent_.get_('role') \
                or None

    def __str__(self):
        s = "{r.key} {r.login}"
        if self.permissions:
            s += " rules:" + str(len(self.permissions))
        if self.expires:
            s += ' expires:{r.expires}'
        else:
            s += ""

        return s.format(r=self)

class NexusOTPs(_AuthorizedNexusCollection):
    _role_permissions = {
        'trust': True,
        'trusted': True,
        '%default': {
            'query':  authorize_owned_query('owner'),
            'update': authorize_owned_update('owner'),
            'create': authorize_owned_create('uuid'),
            'delete': authorize_owned_delete('owner'),
        }
    }
    plaintext_key_ = None

    def get_by_plaintext_(self, plaintext_key):
        """ We need to magically convert the plaintext password
            into its hashed equivalent so we can find it appropriately
        """
        hashed_key = generate_secure_hash(self.parent_.login, plaintext_key)
        return self.get_(hashed_key)

    def create_(self, data_rec):
        """ This creates a new api key token with id
        """
        # Find a unique key. It's very unlikely we'll have a
        # collision but test and address it, just in case
        plaintext_key = None
        while True:
            plaintext_key = secrets.token_urlsafe(24)
            hashed_key = generate_secure_hash(self.parent_.login,plaintext_key)
            if not self.exists_(hashed_key):
                data_rec['key'] = hashed_key
                break

        # Unless an expiry date has been set, we default to 10 minute
        # lifetime
        if 'expires' not in data_rec:
            data_rec['expires'] = timestamp_future(60*10)

        # We do special handling of the plaintext_key since we don't
        # want to store it
        rec = self.instantiate_(data_rec)
        rec.plaintext_key = plaintext_key
        return rec

    def _default_authorize_create(self, user_obj, action, kwargs):
        if kwargs['parent_uid_b64'] != user_obj.uuid:
            raise PermissionError(f"Parent does not equal current user")
        return kwargs

    def _default_authorize_delete(self, user_obj, action, kwargs):

        # Each uid_b64 should be referring to a NexusAPIKey record
        # so we should be abel to get some information like so:
        uid_b64s = []
        for uid_b64 in kwargs['uid_b64s']:
            record = self.get(uid_b64)
            if record.owner_ != user_obj.uuid:
                continue
            uid_b64s.append(uid_b64) 
        kwargs['uid_b64s'] = uid_b64s

        return kwargs

    def vacuum_(self):
        """ This should be run periodically (probably will be done via cron)
            to remove old and stale OTP entries from the database
        """

        for c in self:
            if c.expired_():
                c.delete_()

