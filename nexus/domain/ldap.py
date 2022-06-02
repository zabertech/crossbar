import re
import pathlib
import ruamel.yaml

from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, SUBTREE
from ldap3.utils.conv import escape_filter_chars

from izaber import config, app_config
from izaber.startup import request_initialize, initializer

from nexus.orm import *

from nexus.log import log

"""
LDAPService has three modes of operation.

################################################
# Inactive Mode
################################################

Leaving information out of the config will deactivate LDAP as a source of information
from nexus. So something like the following will prevent this code from connecting and
force the system to use only internal databases


default:
  nexus: {}

################################################
# Live Mode
################################################

If the izaber.yaml file has the standard live configuration, it will use ldap3
to connect to an actual LDAP server

default:
  nexus:
      ldap:
          server:
              host: 'dc2.id.izaber.com'
              port: 636
              use_ssl: True
          login_template: '{login}@id.izaber.com'
          db_login: 'generic-ldap'
          db_password: '[LOWSECURITYPASSWORD]'
          basedn: 'dc=id,dc=izaber,dc=com'
          user_base: 'dc=id,dc=izaber,dc=com'
          user_filter: '(&(objectCategory=person)(samaccountname=*))'
          group_base: 'dc=id,dc=izaber,dc=com'
          group_filter: '(&(objectCategory=group)(name=*))'

################################################
# Mock Mode
################################################

Just for testing, loads information from a local YAML file for data

default:
  nexus:
      ldap:
          server:
              host: 'file://path/to/ldap-mock-data.yaml'

The mock-ldap.yaml file should contain:

groups:
    [DN1]
      attributes:
        - cn, etc
        ...
      dn: [DN1]
    [DNn]
      attributes:
        - cn, etc
        ...
      dn: [DNn]

users:
    [DN1]
      attributes:
        - cn, etc
        ...
      dn: [DN1]
    [DNn]
      attributes:
        - cn, etc
        ...
      dn: [DNn]

"""

class LDAPServer:

    default_user_attributes = [
              'sAMAccountName',
              'memberOf',
              'name',
              'mail',
              'ipPhone',
              'userAccountControl',
              'userPrincipalName',
            ]

    def __init__(self, config):
        self.config = config

        server_config = self.config['server']
        self.server = Server(**server_config)
        self._users_cached = None
        self._groups_cached = None

    def authenticate(self, login, password):
        """ Returns a true value if the login/password provided are able to
            bind to LDAP
        """
        try:
            if not self.server:
                log.warn(f"LDAP No server found.")
                return False
            conn = Connection(
                        self.server,
                        auto_bind=True,
                        user=str(
                            self.config.login_template.format(
                                login=login)),
                        password=str(password),
                    )
            return True
        except Exception as ex:
            log.warn(f"LDAP auth fail: "{login}" due to {ex}")
            return False

    def connect(self):
        """ Returns a connection to the LDAP server with the query user
        """
        if not self.server:
            return False
        try:
            conn = Connection(
                    self.server,
                    auto_bind=True,
                    user=self.config.login_template.format(
                            login=self.config.db_login),
                    password=self.config.db_password
                  )
            return conn
        except Exception as ex:
            #log.error(f"Unable to create connection to LDAP server {self.server} due to exception <{ex}>")
            return False

    def user_get(self, login, attributes=None):
        """ Fetches detailed information about a single user
            identified by the login (which then gets converted into
            the upn)
        """
        conn = self.connect()

        upn_search_filter = f"({self.config.login_attribute}="\
                                f"{escape_filter_chars(login)})"

        if not attributes:
            attributes = self.default_user_attributes
        conn.search(
            self.config.user_base,
            upn_search_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )

        for e in conn.entries:
            entry = dict(e.entry_attributes_as_dict)
            entry['dn'] = e.entry_dn
            return entry

        return


    def users_raw(self, attributes=None, force=False):
        """ Gets the raw list of users from the LDAP domain. Note that
            this query caches
        """
        conn = self.connect()

        conn.search(
            self.config.user_base,
            self.config.user_filter,
            search_scope=SUBTREE,
            attributes=attributes or self.default_user_attributes
        )

        entries = []
        self.users_cached = entries
        for e in conn.entries:
            entry = dict(e.entry_attributes_as_dict)
            entry['dn'] = e.entry_dn
            entries.append(entry)
        return entries

    def groups_raw(self, attributes=None, force=False):
        """ Gets the raw list of groups from the LDAP domain. Note that
            this query caches
        """
        # Return nothing if we aren't using ldap
        if not self.server: return []

        if not force and self._groups_cached:
            return self._groups_cached

        conn = self.connect()
        conn.search(
            self.config.group_base,
            self.config.group_filter,
            search_scope=SUBTREE,
            attributes=[
              'userPrincipalName',
              'name',
              'sAMAccountName',
              'groupType',
              'member',
            ]
        )
        entries = []
        self._groups_cached = entries
        for e in conn.entries:
            entry = dict(e.entry_attributes_as_dict)
            entry['dn'] = e.entry_dn
            entries.append(entry)

        return entries

class LDAPMock:
    def __init__(self, **kwargs):
        self.data = None

        host = kwargs.get('host') or ''
        data_source = re.search(r'file://(.*)',host)
        if not data_source: return

        data_fpath = data_source.group(1)
        if not data_fpath: return
        data_fpath = pathlib.Path(data_fpath)

        if not data_fpath.exists(): return


        # Global YAML Serializer
        yaml = ruamel.yaml.YAML()
        yaml.compact(seq_seq=False)

        self.data = yaml.load(
                        data_fpath.open('r')
                    )

    def authenticate(self, login, password):
        raise NotImplementedError(f"Unable to authenticate in mock object")

    def groups_raw(self, attributes=None, force=False):
        if not self.data:
            return

        entries = []
        for e in self.data['groups']:
            entry = dict(e['attributes'])
            entry['dn'] = e['dn']
            entries.append(entry)
        return entries


    def users_raw(self, attributes=None, force=False):
        if not self.data:
            return

        entries = []
        for e in self.data['users']:
            entry = dict(e['attributes'])
            entry['dn'] = e['dn']
            entries.append(entry)
        return entries


    def user_get(self, login, attributes=None):
        """ Fetches detailed information about a single user
            identified by the login (which then gets converted into
            the upn)
        """
        if not self.data:
            return

        entries = []
        for e in self.data['users']:
            entry = dict(e['attributes'])
            if entry['sAMAccountName'] != login:
                continue
            entry['dn'] = e['dn']
            return entry

        return


class LDAPService:
    def __init__(self):
        self.server = None

    def load_config(self, ldap_config ):
        self.config = DictObject(noerror=True, **ldap_config)

        if not self.config.server:
            return

        scfg = DictObject(noerror=True, **self.config.server)

        if not scfg.host:
            return

        m = re.search(r'file://(.*)', scfg.host)
        if m:
            self.server = LDAPMock(**scfg)
        else:
            self.server = LDAPServer(self.config)


    def authenticate(self, login, password):
        """ Returns a true value if the login/password provided are able to
            bind to LDAP
        """
        try:
            return self.server.authenticate( login, password )
        except Exception as ex:
            return False

    def users_raw(self, attributes=None, force=False):
        """ Gets the raw list of users from the LDAP domain. Note that
            this query caches
        """
        # Return nothing if we aren't using ldap
        if not self.server: return []
        return self.server.users_raw( attributes, force )

    def groups_raw(self, attributes=None, force=False):
        """ Gets the raw list of groups from the LDAP domain. Note that
            this query caches
        """
        # Return nothing if we aren't using ldap
        if not self.server: return []
        return self.server.groups_raw( attributes, force )

    def groups_lookup(self, force=False):
        # Return nothing if we aren't using ldap
        if not self.server: return []

        # Need to get a list of groups first for the lookup
        groups_lookup = {}
        for group_rec in self.groups_raw(force=force):
            groups_lookup[group_rec['dn']] = group_rec

        return groups_lookup

    def user_normalize(self, entry, groups_lookup=None):
        """ Converts a user's ldap entry into the standardized format expected
            by the rest of the nexus system
        """

        if not entry:
            return

        column_mappings = {
          'login': 'sAMAccountName',
          'email': 'mail',
          'name': 'name',
          'upn': 'userPrincipalName',
        }

        user_data = {
          'ldap': entry,
          'auth_source': 'ldap',
        }

        # Remap certain entries
        for name, ldap_name in column_mappings.items():
            value = entry[ldap_name]
            user_data[name] = value and value[0] or ''

        # Determine if the user is still active
        uac = entry['userAccountControl'][0]
        user_data['enabled'] = not uac & 0x02

        # Handle the memberships
        memberships = user_data['memberships'] = []

        # No need to go further if the user is not a
        # member of any groups
        if not entry['memberOf']:
            return user_data

        # Need to get a list of groups first for the lookup
        if not groups_lookup:
            groups_lookup = self.groups_lookup(force=True)

        for group_dn in entry['memberOf']:
            group_rec = groups_lookup[group_dn]
            if not group_rec: continue
            # FIXME:
            group_upn = group_rec['sAMAccountName']
            memberships.append(group_upn)
        user_data['memberships'] = memberships

        return user_data

    def users(self):
        """ Fetches a list of users from the LDAP domain with a small
            selection of metadata
        """
        # Return nothing if we aren't using ldap
        if not self.server: return []

        # Need to get a list of groups first for the lookup
        groups_lookup = self.groups_lookup(force=True)

        column_mappings = {
          'login': 'sAMAccountName',
          'email': 'mail',
          'name': 'name',
          'upn': 'userPrincipalName',
        }
        entries = []
        for entry in self.users_raw():
            user_data = self.user_normalize(entry, groups_lookup)
            entries.append(user_data)
        return entries

    def user_get(self, login):
        """ Fetches the detailed information about a user from ldap
        """
        # Return nothing if we aren't using ldap
        if not self.server: return None
        entry = self.server.user_get(login)
        return self.user_normalize(entry)

    def groups(self):
        """ Fetches all the groups from the LDAP domain with a small
            selection of metadata
        """
        # Return nothing if we aren't using ldap
        if not self.server: return []

        column_mappings = {
          'login': 'sAMAccountName',
          'email': 'mail',
          'name': 'name',
        }
        entries = []
        for entry in self.groups_raw():
            group_data = {
                    'ldap': entry,
                    'auth_source': 'ldap',
                }
            entries.append(group_data)

        return entries

ldap = LDAPService()

@initializer('nexus-ldap')
def load_config(**options):
    request_initialize('config',**options)
    try:
        ldap.load_config(config.nexus.ldap.dict())
    except ( AttributeError, KeyError ):
        #log.info(f"SKIPPING LDAP CONFIGURATION AS NO SETTINGS FOUND")
        pass

