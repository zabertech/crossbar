import sys
import os
import pathlib
import shutil

# Now we can continue on with the normal load process
import datetime
import pytz
import time
import subprocess
import socket
from pprint import pprint

import passlib.hash
import secrets
import pytest

# Setup for proper pathing for libs and data
LIB_PATH = pathlib.Path(__file__).resolve().parent
TEST_PATH = LIB_PATH.parent
DATA_PATH = TEST_PATH / 'data'

# Setup for proper pathing for libs and data
sys.path.insert(1, LIB_PATH)
os.chdir(DATA_PATH)

from izaber import initialize, config
from izaber.startup import request_initialize, initializer
from izaber.date import DateTimeUTC, DateTimeLocal

from nexus.constants import *
from nexus.domain import *
from nexus.orm.common import RECORD_CACHE

import lib.common as common
import lib.ldap
from lib.launcher import *

def reset_env():
    """ Does a complete reset of the directories
    """

    RECORD_CACHE.clear()

    # Create some directories we'll need
    create_dirs = [
                f"db",
                f"db/users",
                f"db/roles",
                f"db/cookies",
                f"db/uris",
                f"db/uuids",
                f"db/rosters",
            ]
    for create_path in create_dirs:
        cpath = pathlib.Path(create_path)
        if cpath.exists():
            shutil.rmtree(cpath)
        cpath.mkdir(parents=True,exist_ok=True)

    # Create the ldap test files
    lib.ldap.generate_mock_data(
                group_count=10,
                user_count=100,
                output_fpath='ldap-mock-data.yaml',
                groupings = [ 90, 33, 29, 23, 20, 10, 10, 5 ]
            )

def create_user(role=DEFAULT_ROLE):
    # Create a random user
    profile = common.profile()
    password = secrets.token_hex(16)
    login = profile['username']
    user_rec = {
          'login': login,
          'plaintext_password': password,
          'role': role,
          'name': profile['name'],
          'source': AUTH_SOURCE_LOCAL,
          'email': profile['mail'],
          'upn': f"{login}@nexus",
      }

    user_obj = db.users.create_(user_rec)

    return login, password, user_rec, user_obj

def create_roles():
    # Create the set of default roles that we'll
    # need for testing

    roles = {
        'public': [
                ['public.*', 'crsp'],
                ['system.roster.query', 'c'],
                ['roster.*', 'oq'],
            ],
        'frontend': [
                ['public.*', 'crsp'],
                ['frontend.*', 'crsp'],
                ['reauth.*', 'c+r+'],
                ['docsrequired.*', 'cr!'],

                # Authentication
                ['auth.whoami', 'c'],
                ['auth.authenticate', 'c'],
                ['auth.reauthenticate', 'c'],
                ['auth.reauthenticate_expire', 'c'],
                ['auth.is_reauthenticated', 'c'],
                ['auth.extend_reauthenticate', 'c'],
                ['auth.refresh_authorizer', 'c'],

                ['my.apikeys.list', 'c'],
                ['my.apikeys.create', 'c'],
                ['my.apikeys.delete', 'c'],

                ['my.metadata.get', 'c'],
                ['my.metadata.set', 'c'],
                ['my.metadata.delete', 'c'],

                ['ad.users', 'c'],
                ['ad.groups', 'c'],
                ['directory.users', 'c'],
                ['directory.groups', 'c'],

                # ORM
                ['system.db.query', 'c'],
                ['system.db.create', 'c'],
                ['system.db.update', 'c'],
                ['system.db.upsert', 'c'],
                ['system.db.delete', 'c'],

                # Documentation
                ['system.document.*', 'c'],

                # Roster Support
                ['system.roster.*', 'c'],
                ['roster.*', 'oq' ],
            ],
        'backend': [
                ['*', 'crspoq'],
            ],
    }

    for role, uris in roles.items():
        role_obj = db.roles.create_({ 'role': role })
        for uri, perms in uris:
            role_obj.permissions.append({
                    'uri': 'com.izaber.wamp.' + uri,
                    'perms': perms
                })
            role_obj.permissions.append({
                    'uri': uri,
                    'perms': perms
                })

        role_obj.save_()
    db.roles.refresh_uri_authorizer_()


@initializer('nexus-testing', before=['nexus-db'])
def load_config(**options):
    #reset_env()
    request_initialize('nexus-db',**options)
    #create_roles()


