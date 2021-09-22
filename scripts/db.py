#!/usr/bin/env python3

import sys
import os
import pathlib

# Setup for proper pathing for libs and data
dir_path = os.path.dirname(os.path.realpath(__file__))
cwd = pathlib.Path(os.getcwd())
os.chdir(dir_path)
sys.path.insert(1, f"{dir_path}/../lib")

__doc__ = f"""
Usage:
  db.py users list [options]
  db.py users info <login> [options]
  db.py users create <login> [<password>] [<role>] [options]
  db.py users edit <login> [options]
  db.py users delete <login> [options]
  db.py users dump <login> [<path>] [options]
  db.py users load <login> [<path>] [options]
  db.py users password <login> [options]
  db.py users sync [options]
  db.py apikeys list [<login>] [options]
  db.py apikeys info <uuid> [options]
  db.py apikeys create <login> [<description>] [options]
  db.py apikeys edit <uuid> [options]
  db.py apikeys delete <uuid> [options]
  db.py apikeys dump <uuid> [<path>] [options]
  db.py apikeys load <uuid> [<path>] [options]
  db.py roles list [options]
  db.py roles create <role> [options]
  db.py roles info <uuid> [options]
  db.py roles edit <uuid> [options]
  db.py roles dump <uuid> [<path>] [options]
  db.py roles load <uuid> [<path>] [options]
  db.py uris list [<role>] [options]
  db.py devdb create [<admin_user> <admin_pass>] [options]
  db.py database reindex [options]
  db.py database vacuum [options]
  db.py database destroy [options]

Options:
  -h --help     Show help
  --cbdir=<cbdir>   Nexus `/data` Directory [default: {dir_path}/../data]


Description:

  Manages the nexus internal file database

"""

import shutil
import docopt
import getpass

args = docopt.docopt(__doc__)

cbdir = args['--cbdir']
os.chdir(cbdir)

from izaber import initialize, config

# Now we can load the full set of izaber/nexus libraries
from nexus.domain import controller
from nexus.domain.db import db
from nexus.constants import AUTH_SOURCE_LOCAL

class Commands:
    verbs = ['list', 'info', 'create', 'edit', 'delete', 'dump', 'load', 'sync']

    def __init__(self, args):
        self.args = args

    def get_uuid(self, uuid, expect=None):
        obj = db.get(uuid)
        if expect and obj.record_type_ != expect:
            raise KeyError(f"UUID does not refer to type {expect}")
        return obj

    def get_yaml(self, uuid, expect=None):
        obj = self.get_uuid(uuid, expect)
        with obj.yaml_fpath_.open('r') as f:
            buf = f.read()
        return buf

    def do_list(self):
        raise NotImplementedError('do_list must be implemented!')

    def do_create(self):
        raise NotImplementedError('do_create must be implemented!')

    def do_edit(self):
        raise NotImplementedError('do_edit must be implemented!')

    def do_delete(self):
        raise NotImplementedError('do_delete must be implemented!')

    def do_dump(self):
        raise NotImplementedError('do_dump must be implemented!')

    def do_load(self):
        raise NotImplementedError('do_load must be implemented!')

    def do_sync(self):
        raise NotImplementedError('do_sync must be implemented!')

    def process_command(self):
        for verb in self.verbs:
            if not self.args[verb]:
                continue
            getattr(self,f'do_{verb}')()
            break
        else:
            raise Exception('Unknown commandline verb provided')

class UserCommands(Commands):
    verbs = ['list', 'info', 'create', 'edit', 'delete', 'dump', 'load', 'sync', 'password']

    def do_list(self):
        results = db.query(
                            'users',
                            sort=[['login','asc']],
                            conditions=[
                                    ['enabled','=',True]
                                ]
                        )
        for result in results['records']:
            print(f"uuid:{result.uuid} login:{result.login} role:{result.role}")

    def do_create(self):
        login = self.args['<login>']
        password = self.args['<password>'] or 'foo'
        role = self.args['<role>'] or DEFAULT_ROLE
        user_obj = db.users.create_({
                                        'login': login,
                                        'plaintext_password': password,
                                        'role': role,
                                        'name': login,
                                        'source': AUTH_SOURCE_LOCAL,
                                        'upn': f"{login}@nexus",
                                    })

    def do_info(self):
        login = self.args['<login>']
        user_obj = db.users[login]
        print( '---------------------------------------------------')
        print(f"| YAML:")
        print(f"|   {user_obj.yaml_fpath_}")
        print( '---------------------------------------------------')
        print(user_obj.yaml_())

    def do_delete(self):
        login = self.args['<login>']
        user_obj = db.users[login]
        user_obj.remove_()

    def do_edit(self):
        login = self.args['<login>']
        user_obj = db.users[login]
        yaml_fpath = user_obj.yaml_fpath_
        editor = os.environ.get('EDITOR') or '/usr/bin/editor'
        os.system(f"{editor} {yaml_fpath}")

    def do_dump(self):
        login = self.args['<login>']
        user_obj = db.users[login]
        if self.args['<path>']:
            path = cwd / pathlib.Path(self.args['<path>'])
            with path.open('w') as f:
                yaml_dump(user_obj.data_rec_, f)
        else:
            print(user_obj.yaml_())

    def do_load(self):
        login = self.args['<login>']
        user_obj = db.users[login]

        # Get the data_rec for the update
        if self.args['<path>']:
            path = cwd / pathlib.Path(self.args['<path>'])
            with path.open('r') as f:
                data_rec = yaml_load(f)
        else:
            buf = sys.stdin.read()
            data_rec = yaml_loads(buf)

        # Then do the update
        for k in ['enabled','role','source','password','email','upn','name','plaintext_password']:
            if k not in data_rec: continue
            user_obj[k] = data_rec[k]
        user_obj.save_()

    def do_sync(self):
        controller.sync()

    def do_password(self):
        login = self.args['<login>']
        user_obj = db.users[login]

        password = getpass.getpass('New Password: ')
        user_obj['plaintext_password'] = password
        user_obj.save_()



class APIKeyCommands(Commands):
    def do_list(self):
        conditions = []
        login = self.args['<login>']
        if login:
            conditions.append(['owner_.login','=',login])
        results = db.query(
                            'apikeys',
                            conditions=conditions,
                            sort=[['owner_.login','asc']]
                        )
        for result in results['records']:
            print(f"uuid:{result.uuid} login:{result.owner_.login} description:{result.description}")

    def do_create(self):
        login = self.args['<login>']
        description = self.args['<description>'] or 'CLI Generated'
        user_obj = db.users[login]
        apikey_obj = user_obj.apikeys.create_({
                                        'description': description
                                    })

    def do_info(self):
        uuid = self.args['<uuid>']
        key_obj = self.get_uuid(uuid,'apikey')
        print( '---------------------------------------------------')
        print(f"| YAML:")
        print(f"|   {key_obj.yaml_fpath_}")
        print( '---------------------------------------------------')
        print(key_obj.yaml_())

    def do_delete(self):
        uuid = self.args['<uuid>']
        key_obj = db.get(uuid)
        if key_obj.record_type_ != 'apikey':
            raise KeyError(f"UUID does not refer to an APIKey")
        key_obj.remove_()

    def do_edit(self):
        uuid = self.args['<uuid>']
        key_obj = db.get(uuid)
        if key_obj.record_type_ != 'apikey':
            raise KeyError(f"UUID does not refer to an APIKey")
        yaml_fpath = key_obj.yaml_fpath_
        editor = os.environ.get('EDITOR') or '/usr/bin/editor'
        os.system(f"{editor} {yaml_fpath}")


    def do_dump(self):
        uuid = self.args['<uuid>']
        obj = db.get(uuid)
        if self.args['<path>']:
            path = cwd / pathlib.Path(self.args['<path>'])
            with path.open('w') as f:
                yaml_dump(obj.data_rec_, f)
        else:
            print(obj.yaml_())

    def do_load(self):
        uuid = self.args['<uuid>']
        obj = db.get(uuid)

        # Get the data_rec for the update
        if self.args['<path>']:
            path = cwd / pathlib.Path(self.args['<path>'])
            with path.open('r') as f:
                data_rec = yaml_load(f)
        else:
            buf = sys.stdin.read()
            data_rec = yaml_loads(buf)

        # Then do the update
        for k in ['plaintext_key', 'description', 'expires', 'permissions']:
            if k not in data_rec: continue
            obj[k] = data_rec[k]
        obj.save_()


class RoleCommands(Commands):

    def do_list(self):
        conditions = []
        results = db.query('roles')
        for result in results['records']:
            print(f"uuid:{result.uuid} login:{result.role}")

    def do_create(self):
        role = self.args['<role>']
        apikey_obj = db.roles.create_({'role':role})

    def do_info(self):
        uuid = self.args['<uuid>']
        key_obj = self.get_uuid(uuid,'role')
        print( '---------------------------------------------------')
        print(f"| YAML:")
        print(f"|   {key_obj.yaml_fpath_}")
        print( '---------------------------------------------------')
        print(key_obj.yaml_())

    def do_edit(self):
        uuid = self.args['<uuid>']
        key_obj = db.get(uuid)
        if key_obj.record_type_ != 'role':
            raise KeyError(f"UUID does not refer to an Role")
        yaml_fpath = key_obj.yaml_fpath_
        editor = os.environ.get('EDITOR') or '/usr/bin/editor'
        os.system(f"{editor} {yaml_fpath}")

    def do_dump(self):
        uuid = self.args['<uuid>']
        obj = db.get(uuid)
        if self.args['<path>']:
            path = cwd / pathlib.Path(self.args['<path>'])
            with path.open('w') as f:
                yaml_dump(obj.data_rec_, f)
        else:
            print(obj.yaml_())

    def do_load(self):
        uuid = self.args['<uuid>']
        obj = db.get(uuid)

        # Get the data_rec for the update
        if self.args['<path>']:
            path = cwd / pathlib.Path(self.args['<path>'])
            with path.open('r') as f:
                data_rec = yaml_load(f)
        else:
            buf = sys.stdin.read()
            data_rec = yaml_loads(buf)

        # Then do the update
        for k in ['plaintext_key', 'description', 'expires', 'permissions']:
            if k not in data_rec: continue
            obj[k] = data_rec[k]
        obj.save_()


class URICommands(Commands):

    def do_list(self):
        conditions = []
        role = self.args['<role>']
        if role:
            conditions.append(['role','=',role])
        results = db.query(
                            'roles',
                            conditions=conditions,
                            sort=[['role','asc']]
                        )
        for result in results['records']:
            print("\nrole:", result.role)
            for perm in result['permissions']:
              print(f"  - {perm['uri']} - {perm['perms']}")


def devdb_create(args):
    """ Creates an initial database of roles and users for development purposes
    """
    roles = {
        'public': [
                ['com.izaber.wamp.public', 'crsp'],
                ['com.izaber.wamp.discovery.kncknc', 'p'],
                ['com.izaber.wamp.discovery.whsthr', 's'],
            ],
        'frontend': [
                ['com.izaber.wamp.public', 'crsp'],
                ['com.izaber.wamp.frontend', 'crsp'],
                ['com.izaber.wamp.reauth', 'c+r+'],

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

                # ORM
                ['com.izaber.wamp.system.db.query', 'c'],
                ['com.izaber.wamp.system.db.create', 'c'],
                ['com.izaber.wamp.system.db.update', 'c'],
                ['com.izaber.wamp.system.db.upsert', 'c'],
                ['com.izaber.wamp.system.db.delete', 'c'],

                # Zerp allow for any db
                ['com.izaber.wamp./zerp.*/.*', 'cs'],

                # Consumption Graph
                ['com.izaber.wamp.graphs.product_graph_consumption', 'c'],
            ],
        'backend': [
                ['com.izaber.wamp.*', 'crsp'],
            ],
    }

    for role, uris in roles.items():
        role_obj = db.roles.create_({ 'role': role })

        # Map the permissions that already exist
        permissions_lookup = {}
        for permission in role_obj.permissions:
            uri = permission['uri']
            permissions_lookup[uri] = permission

        # Now update or amend as required
        for uri, perms in uris:
            if uri in permissions_lookup:
                permissions_lookup[uri]['perms'] = perms
            else:
                role_obj.permissions.append({
                        'uri': uri,
                        'perms': perms
                    })
        role_obj.save_()

    # We need to find the user from the izaber.yaml file if no
    # user has been specified
    if not args['<admin_user>']:
        args['<admin_user>'] = config.wamp.connection.username
        args['<admin_pass>'] = config.wamp.connection.password

    # Now create the admin user
    login = args['<admin_user>']
    password = args['<admin_pass>']
    user_rec = {
            'login': login,
            'plaintext_password': password,
            'role': 'trust',
            'name': f"DevDB Autogenerated Admin",
            'source': AUTH_SOURCE_LOCAL,
            'email': f"{login}@nexus",
            'upn': f"{login}@nexus",
        }
    user_obj = db.users.create_(user_rec)

def main(args):
    if args['users']:
        UserCommands(args).process_command()
    elif args['apikeys']:
        APIKeyCommands(args).process_command()
    elif args['roles']:
        RoleCommands(args).process_command()
    elif args['uris']:
        URICommands(args).process_command()
    elif args['devdb']:
        devdb_create(args)
    elif args['database']:
        if args['destroy']:
            cpath = pathlib.Path('db')
            if cpath.exists():
                shutil.rmtree(cpath)
            cpath.mkdir(parents=True,exist_ok=True)
        elif args['reindex']:
            db.reindex_uuids()
        elif args['vacuum']:
            db.vacuum_()

if __name__ == '__main__':
    initialize('nexus-db-manager')
    main(args)

