import sys
import os
import pathlib
import secrets
import json

# Setup for proper pathing for libs and data
#dir_path = os.path.dirname(os.path.realpath(__file__))
#cwd = pathlib.Path(os.getcwd())
#os.chdir(dir_path)
#sys.path.insert(1, f"{dir_path}/..")

DOC_TEMPLATE = """
Usage:
  {script_name} users list [options]
  {script_name} users info <login> [options]
  {script_name} users create <login> [<password>] [<role>] [options]
  {script_name} users edit <login> [options]
  {script_name} users delete <login> [options]
  {script_name} users dump <login> [<path>] [options]
  {script_name} users load <login> [<path>] [options]
  {script_name} users password <login> [options]
  {script_name} users sync [options]
  {script_name} apikeys list [<login>] [options]
  {script_name} apikeys info <uuid> [options]
  {script_name} apikeys create <login> [<description>] [options]
  {script_name} apikeys edit <uuid> [options]
  {script_name} apikeys delete <uuid> [options]
  {script_name} apikeys dump <uuid> [<path>] [options]
  {script_name} apikeys load <uuid> [<path>] [options]
  {script_name} roles list [options]
  {script_name} roles create <role> [options]
  {script_name} roles info <uuid> [options]
  {script_name} roles edit <uuid> [options]
  {script_name} roles dump <uuid> [<path>] [options]
  {script_name} roles load <uuid> [<path>] [options]
  {script_name} uris list [<role>] [options]
  {script_name} devdb create [<admin_user> <admin_pass>] [options]
  {script_name} testdb create [<admin_user> <admin_pass>] [options]
  {script_name} database reindex [options]
  {script_name} database vacuum [options]
  {script_name} database destroy [options]
{extra_commands}
Options:
  -h --help     Show help
  --cbdir=<cbdir>   Nexus `data` Directory [default: {data_path}]
{extra_options}
Description:

  Manages the nexus internal file database
{extra_description}
"""

import shutil
import docopt
import getpass

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
        for k in ['enabled', 'role', 'source', 'password',
                    'email', 'upn', 'name', 'plaintext_password']:
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
            print(f"uuid:{result.uuid} login:{result.owner_.login} "\
                    f"description:{result.description}")

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

    # This creates a summary of all the roles/users created so that
    # we can hand it over to another program/script that might not
    # have access to the DB tooling required to access the database
    CREATE_SUMMARY = {
        'roles': {},
        'users': {},
    }

    roles = {
        'public': [
            ['com.izaber.wamp.public', 'crsp'],
            ['com.izaber.wamp.discovery.kncknc', 'p'],
            ['com.izaber.wamp.discovery.whsthr', 's'],
            ['com.izaber.wamp./dashboard:.*:dashboardRegistry/.get', 'c'],
            ['com.izaber.wamp.system.roster.query', 'c'],
            ['roster.*', 'q'],
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

            # System preferences
            ['com.izaber.wamp.system.preference.get', 'c'],
            ['com.izaber.wamp.system.preference.set', 'c'],
            ['com.izaber.wamp.system.is_reauthenticated', 'c'],
            ['com.izaber.wamp.system.extend_reauthenticate', 'c'],

            # Zerp allow for any db
            ['com.izaber.wamp./zerp.*/.*', 'cs'],

            # Allow logged in user to get registry
            ['com.izaber.wamp./dashboard:.*:dashboardRegistry/.get', 'c'],
            # Open up all calls to dashboard for a logged in user
            ['com.izaber.wamp./dashboard:.*/.*', 'cs'],
            # Allows calls to directory
            ['com.izaber.wamp.directory.users', 'c'],
            ['com.izaber.wamp.directory.groups', 'c'],
            # Not sure if this should be allowed by default, but something is calling it from frontend
            ['com.izaber.wamp.notification.router.registerDestination', 'c'],

            # Handlings roster requests
            ['com.izaber.wamp.system.roster.register', 'c'],
            ['com.izaber.wamp.system.roster.unregister', 'c'],
            ['com.izaber.wamp.system.roster.query', 'c'],
            ['roster.*', 'oq'],

            # Consumption Graph
            ['com.izaber.wamp.graphs.product_graph_consumption', 'c'],

        ],
        'backend': [
            ['com.izaber.wamp.*', 'crsp'],
            ['roster.*', 'oq'],
        ],
    }

    # wamp_zerp needs to be in place because calls from dashboard need a
    # valid user in zerp After migration module is ready for zerp wamp_zerp
    # can be removed and use a fully fictional user
    users = {
        'dev_backend_user': {
            'password': 'dev_backend_pass',
            'name': 'backend user for dev',
            'role': 'backend',
            'source': AUTH_SOURCE_LOCAL,
        },
        'wamp_zerp': {
            'password': 'dev_backend_pass',
            'name': 'Manual entry for wamp_zerp',
            'role': 'backend',
            'source': AUTH_SOURCE_LOCAL,
        }
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

        CREATE_SUMMARY['roles'][role_obj.role] = role_obj.dict_()

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
    user_rec.update(user_obj.dict_())
    CREATE_SUMMARY['users'][login] = user_rec

    for login, data in users.items():
        rec = {
            'login': login,
            'plaintext_password': data.get('password'),
            'role': data.get('role'),
            'name': data.get('name'),
            'source': data.get('source'),
            'email': f"{login}@nexus",
            'upn': f"{login}@nexus",            
        }
        user_obj = db.users.create_(rec)
        user_rec.update(user_obj.dict_())
        CREATE_SUMMARY['users'][login] = user_rec

    return CREATE_SUMMARY


def testdb_create(args):
    """ Creates the initial devdb database then adds a bunch of users
        for testing tool purposes. This then creates a file named
        ..../data/snapshot.json that holds all the information in
        an json structured document so it can be used to login and do
        further testing
    """
    CREATE_SUMMARY = devdb_create(args)

    user_count = int(args.get('<user_count>',100))
    password_length = 12

    full_count = 0
    for role_name, role_data in CREATE_SUMMARY['roles'].items():
        for i in range(user_count):
            full_count += 1

            new_password = secrets.token_urlsafe(password_length)
            login = f"{role_name}-{i}"
            name = f"{role_name}{i} Name{i}"
            user_rec = {
                'login': login,
                'plaintext_password': new_password,
                'role': '',
                'name': name,
                'source': 'local',
                'email': f"{login}@nexus",
                'upn': f"{login}@nexus",            
            }
            user_obj = db.users.create_(user_rec)
            user_rec.update(user_obj.dict_())
            CREATE_SUMMARY['users'][login] = user_rec

    # Let's dump the JSON file in a file named snapshot.json
    # in the db path
    db_snapshot_fpath = db.base_path_.parent / "snapshot.json"
    with db_snapshot_fpath.open('w') as f:
        json.dump(CREATE_SUMMARY, f)

    return CREATE_SUMMARY

class Runner:
    def parse(self, doc_template=None, **args):
        if doc_template is None:
            doc_template = DOC_TEMPLATE.format(**args)
        args = docopt.docopt(doc_template)
        return args

    def handle_args(self, args):

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
        elif args['testdb']:
            testdb_create(args)
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
        else:
            raise Exception(f'Unknown arguments: {args}')

    def invoke(
            self,
            doc_template=None,
            script_name=None,
            extra_commands='',
            extra_options='',
            extra_description='',
            data_path='/data',
        ):

        if script_name is None:
            script_name = pathlib.Path(sys.argv[0]).name

        # Note that docopt captures --help here as well
        args = self.parse(
                    doc_template = doc_template,
                    script_name = script_name,
                    extra_commands = extra_commands,
                    extra_options = extra_options,
                    extra_description = extra_description,
                    data_path = data_path,
                )

        # We'll put ourselves in the proper directory
        cwd = os.getcwd()
        try:
            os.chdir(args['--cbdir'])
            initialize('nexus-db-manager')
            self.handle_args(args)

        # Pur ourselves back to where we need to be
        finally:
            os.chdir(cwd)

# For script exec
def run(*args,**kwargs):
    Runner().invoke(*args,**kwargs)
