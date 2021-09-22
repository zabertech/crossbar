import sys
import os
import pathlib
import shutil

# Setup for proper pathing for libs and data
dir_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(dir_path)
sys.path.insert(1, f"{dir_path}/../../lib")
os.chdir(f"{dir_path}/../data")

# Now we can continue on with the normal load process
import datetime
import pytz
import time
import subprocess
import socket
from pprint import pprint

from izaber import initialize, config
from izaber.startup import request_initialize, initializer
from izaber.date import DateTimeUTC, DateTimeLocal

from faker import Faker
faker = Faker()

import passlib.hash
import secrets
import pytest

from nexus.constants import *
from nexus.domain import *
from nexus.orm.common import RECORD_CACHE

import lib.ldap

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
                f"db/uuids",
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

def create_roles():
    # Create the set of default roles that we'll
    # need for testing

    roles = {
        'public': [
                ['com.izaber.wamp.public.*', 'crsp']
            ],
        'frontend': [
                ['com.izaber.wamp.public.*', 'crsp'],
                ['com.izaber.wamp.frontend.*', 'crsp'],
                ['com.izaber.wamp.reauth.*', 'c+r+'],

                # Authentication
                ['com.izaber.wamp.auth.whoami', 'c'],
                ['com.izaber.wamp.auth.authenticate', 'c'],
                ['com.izaber.wamp.auth.reauthenticate', 'c'],
                ['com.izaber.wamp.auth.reauthenticate_expire', 'c'],
                ['com.izaber.wamp.auth.is_reauthenticated', 'c'],
                ['com.izaber.wamp.auth.extend_reauthenticate', 'c'],
                ['com.izaber.wamp.auth.refresh_authorizer', 'c'],

                ['com.izaber.wamp.my.apikeys.list', 'c'],
                ['com.izaber.wamp.my.apikeys.create', 'c'],
                ['com.izaber.wamp.my.apikeys.delete', 'c'],

                ['com.izaber.wamp.my.metadata.get', 'c'],
                ['com.izaber.wamp.my.metadata.set', 'c'],
                ['com.izaber.wamp.my.metadata.delete', 'c'],

                ['com.izaber.wamp.ad.users', 'c'],
                ['com.izaber.wamp.ad.groups', 'c'],
                ['com.izaber.wamp.directory.users', 'c'],
                ['com.izaber.wamp.directory.groups', 'c'],

                # ORM
                ['com.izaber.wamp.system.db.query', 'c'],
                ['com.izaber.wamp.system.db.create', 'c'],
                ['com.izaber.wamp.system.db.update', 'c'],
                ['com.izaber.wamp.system.db.upsert', 'c'],
                ['com.izaber.wamp.system.db.delete', 'c'],
            ],
        'backend': [
                ['com.izaber.wamp.*', 'crsp'],
            ],
    }

    for role, uris in roles.items():
        role_obj = db.roles.create_({ 'role': role })
        for uri, perms in uris:
            role_obj.permissions.append({
                    'uri': uri,
                    'perms': perms
                })
        role_obj.save_()
    db.roles.refresh_uri_authorizer_()

def launch_nexus():
    """ This starts a copy of nexus on the local server
    """
    cx_env = os.environ
    current_path = pathlib.Path(__file__).resolve()
    cx_env['PYTHONPATH'] = str(current_path.parent.parent.parent / "lib")
    log_level = cx_env.get('LOG_LEVEL', 'warn')
    cx_process =  subprocess.Popen([
                                "crossbar",
                                "start",
                                "--loglevel", log_level,
                            ], env=cx_env)

    # Wait till port 8282 is open. Give up after 60 seconds
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    location = ("127.0.0.1", 8282)
    for i in range(60):
        time.sleep(1)
        result_of_check = a_socket.connect_ex(location)
        if result_of_check == 0:
            break
    else:
        print(f"Port is not open. Giving up though")

    return cx_process

@initializer('nexus-testing', before=['nexus-db'])
def load_config(**options):
    #reset_env()
    request_initialize('nexus-db',**options)
    #create_roles()


