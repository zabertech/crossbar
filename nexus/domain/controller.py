from nexus.constants import AUTH_SOURCE_LOCAL, \
                            AUTH_SOURCE_APIKEY, \
                            AUTH_SOURCE_LDAP, \
                            DEFAULT_ROLE, \
                            PERM_DENY, \
                            PERM_ALLOW, \
                            PERM_REQUIRE_DOCUMENTATION, \
                            ELEVATED_STALE_SECONDS
from nexus.orm import *
from nexus.domain.db import *
from nexus.domain.ldap import ldap
from nexus.log import log

import traceback

##################################################
# Authentication Results
##################################################

class AuthenticationResult(DictObject):
    def __init__(self, user_obj, role, auth_source, opts=None):
        if opts is None:
            opts = {}
        super().__init__(
                    noerror=True,
                    user=user_obj,
                    role=role,
                    auth_source=auth_source,
                    opts=opts,
                )


##################################################
# Controller
##################################################

class Controller:

    # FIXME: Where to get global value
    _cookie_max_age = 60
    _cookie_id_field_length = 24

    def load_config(self):
        pass

    def authenticate_locally(self, login, password):
        """ Uses the local database to perform authentication
            and doesn't look at things like ldap

            There's an important thing to note with the results.

            returning None: means no information about this
               authentication available so no further processing
               required or we just drop out

            returning False: means we deny access

            returning AuthenticationResult instance means we have
               granted access
        """
        user_obj = db.users[login]
        user_obj.reload_()
        if not user_obj:
            return None

        # Drop out if disable
        if not user_obj.enabled:
            return False

        # Check internal authentication
        if user_obj.authenticate(password):
            role = user_obj.role or DEFAULT_ROLE
            return AuthenticationResult(user_obj, role, AUTH_SOURCE_LOCAL)

        # Check API keys next
        key_obj = user_obj.apikeys.get_by_plaintext_(password)
        if not key_obj:
            return None

        # As some keys may have time limits on their usage, we
        # check here to ensure it hasn't been surpassed
        # There's also another check in the authentication block
        if key_obj.expired():
            return False

        role = key_obj.effective_role() or DEFAULT_ROLE
        return AuthenticationResult(user_obj, role, AUTH_SOURCE_APIKEY, 
                  {
                      'permissions': key_obj.permissions,
                      'apikey': key_obj.key,
                  })

    def authenticate(self, login, password):
        """ Returns the role associated with the login and password
            if anything is available
        """
        # Check if the user is managed locally from within nexus
        # in any way.
        local_auth = self.authenticate_locally(login, password)
        if local_auth:
            return local_auth

        # This means we explicitly deny this user access
        if local_auth == False:
            return

        # Use ldap authentication last
        if not ldap.authenticate( login, password ):
            return

        # If the ldap user authenticates and we don't have
        # a user_obj, we should probably create the user in the system
        user_obj = db.users[login]
        if not user_obj:
            user_obj = db.users.create_({
                          'login': login,
                          'source': AUTH_SOURCE_LDAP,
                          'role': DEFAULT_ROLE,
                          'enabled': True,
                        })

        # All authenticated users get a cookie object
        role = user_obj.role or DEFAULT_ROLE
        return AuthenticationResult(user_obj, role, AUTH_SOURCE_LDAP)

    def login (self, login, password, cbtid=None):
        """ This logs a user into the system. This is two tier:
            1. Authenticates the user to verify credentials
            2. Creates the CookieSession tracking to ensure
                private data can be crosslinked across sessions
        """

        # Force the login to be lower case
        login = login.lower()

        res = self.authenticate(login, password)
        if not res:
            return False

        restrictions = res.opts.get('permissions')
        apikey = res.opts.get('apikey')

        # Upon successful login, some critical metadata gets stored in the
        # NexusSession to associate it with the the Crossbar Session
        # and Authentication Cookie
        cookie_obj = cbtid and db.cookies.get_(cbtid)
        if not cookie_obj:
            cookie_obj = db.cookies.create_(
                                {
                                    #'created': util.utcnow(),
                                    'created': time.time(),
                                    'max_age': self._cookie_max_age,
                                },
                                key_length=self._cookie_id_field_length
                            )
        cookie_obj.data = {
                            'restrictions': restrictions,
                            'auth': [ res.auth_source, apikey ],
                            'last_authentication': time.time(),
                        }
        cookie_obj.save_()

        # Into the authextra we then provide information that allows
        # us to track information back
        extra = {
            'cache_id': cookie_obj.uuid,
            'has_restrictions': restrictions and True or False,
        }
        return {
            'role': res.role,
            'extra': extra,
            'authid': login,
            'auth_source': res.auth_source, 
            'cookie_obj': cookie_obj,
        }

    def logout(self, login, cache_id):
        """ All this really does is remove the data associated with a
            session token
        """

        # FIXME This is probably not the right way of handling this
        # We should probably be doing something else...
        cookie_obj = db.get(cache_id,'cookie')
        if not cookie_obj: return
        cookie_obj.delete_()

    def authorize(self, login, role, uri, action, extra=None, options=None):
        """ This will return permissions values depending on whether
            or not the role is allowed to perform the particular
            action on the URI
        """

        if options is None:
            options = {}

        # We validate on the role first. This is necessary especially for
        # anonymous users. They will have been assigned a random auth_id
        # which will not be available in the database. If it does happen
        # to get to the point of trying to query the role, the database will
        # report an error with respect to the being missing (since it's a made
        # up user) and will crash out.
        permission = db.roles.uri_permissions_(role, uri, action)

        # If permission is False-y it just means it's a blanket NOT ALLOWED
        # so we'll just short-circuit out
        if not permission:
            return PERM_DENY

        # Now we check to see if the authenticated user has permission to
        # access this URI
        try:
            user_obj = db.users[login]

        except KeyError:
            # Crossbar generates a fake login for any anonymous user. Something like:
            # login = "EWSQ-V775-49PS-H3KT-SRNH-ATXY". This creates a problem when we
            # try and lookup the user to see if they are disabled. So here we check
            # if the user exists and if it doesn't, we're assuming that it's an anon
            # session (only way we'd get here) and simply return the permission because
            # of it.
            return permission

        if not user_obj.enabled:
            return PERM_DENY

        # Get some basic variables
        cache_id = extra.get('cache_id') if extra else None
        cookie_obj = db.get(cache_id, 'cookie')
        auth_data = cookie_obj and cookie_obj.data.get('auth')

        # Validate that the key has not yet expired
        if auth_data and auth_data[0] == AUTH_SOURCE_APIKEY:
            apikey = auth_data[1]
            apikey_obj = user_obj.apikeys.get_(apikey)
            if not apikey_obj:
                return PERM_DENY
            if apikey_obj.expired():
                return PERM_DENY

        # Do we have a session token to lookup? We really only care if there's
        # something saying there's extra restrictions on this
        if permission == PERM_ALLOW and extra and extra.get('has_restrictions'):
            if not cache_id:
                raise ValueError('Missing cache_id when session has restrictions' \
                                 ' associated. Cannot look restrictions up so aborting.')
            key_permissions = cookie_obj.authorize_(uri, action)
            if not key_permissions:
                return PERM_DENY

        # Does this query require documentation? Let's verify if it does
        if permission.require_documentation:
            match = options.get('match') or 'exact'
            key = db.uris.generate_key_( action, match, uri )
            rec = db.uris.get_(key)
            if not rec or not rec.documented():
                return PERM_REQUIRE_DOCUMENTATION

            if not permission.require_elevated:
                return PERM_ALLOW

        # Do we need to test for a recent login?
        if permission.require_elevated:
            if not cache_id:
                raise ValueError('Missing cache_id when session requires elevated' \
                                 ' permissions. Cannot look last auth up so aborting.')
            if cookie_obj.last_authentication_age > ELEVATED_STALE_SECONDS:
                return PERM_DENY
            else:
                return PERM_ALLOW

        return permission

    def reauthenticate(self, login, password, extra):
        """ Updates the last authentication timestamp in the session token
            so the user can access elevated auth required URIs
        """
        if not extra:
            raise ValueError('Missing extra when session requires elevated' \
                             ' permissions. Cannot look last auth up so aborting.')
        if not self.authenticate(login, password):
            log.warning(f"NOPASSWORD: Rejected reauthentication attempt {login}")
            return False

        # We need the session session token to be able to tag the
        # session as reauthenticated
        cache_id = extra.get('cache_id')
        if not cache_id:
            raise ValueError('Missing extra when session requires elevated' \
                             ' permissions. Cannot look last auth up so aborting.')

        cookie_obj = db.get(cache_id,'cookie')

        # Update cookie to that it knows that the most recent `reauth`
        # was now
        cookie_obj.touch_reauthenticate()

        return ELEVATED_STALE_SECONDS

    def reauthenticate_expire(self, extra):
        """ This will flush the current sessions elevated reauthentication
            timer to 0. This will prevent any further elevated auth
            interactions until a reauth is performed
        """
        if not extra: return

        # We need the session session token to be able to tag the
        # session as reauthenticated
        cache_id = extra.get('cache_id')
        db.get(cache_id,'cookie').touch_reauthenticate(time_value=0)

        return True

    def reauthenticate_touch(self, extra):
        """ If the session is reauthenticated status is currently active,
            this will simply refresh the status to the current timestamp
        """
        if not extra:
            return False

        # We need the session session token to be able to tag the
        # session as reauthenticated
        cache_id = extra.get('cache_id')
        cookie_obj = db.get(cache_id,'cookie')
        if not cookie_obj:
            return False

        # Validate that we haven't already lost the reauth status
        age = cookie_obj.last_authentication_age
        if age > ELEVATED_STALE_SECONDS:
            return False

        # Wipe the reauth status
        cookie_obj.touch_reauthenticate()

        return ELEVATED_STALE_SECONDS

    def reauthenticate_remaining(self, extra):
        """ Returns the remaining seconds of reauthenticated validation
            False if not.
        """
        if not extra:
            return False

        # We need the session session token to be able to tag the
        # session as reauthenticated
        cache_id = extra.get('cache_id')
        cookie_obj = db.get(cache_id,'cookie')
        if not cookie_obj:
            return False

        # Wipe the reauth status
        age = cookie_obj.last_authentication_age
        if age > ELEVATED_STALE_SECONDS:
            return False
        return ELEVATED_STALE_SECONDS - age

    def reload(self):
        """ Flush all credential information and force a reload
        """
        db.load_data()

    #####################################################
    # Roster Management/Querying
    #####################################################

    def roster_unregister_session(self, session_id):
        """ Removes all roster entries associated with a particular session_id
        """
        results = db.query(
                    collection_type='rosters',
                    conditions=[
                        ['session_id', '=', session_id]
                    ],
                )

        for hit in results['records']:
            hit.delete_()

        return True

    def roster_register(self, session_id, login, role, roster_name, roster_data, extra):

        permission = self.authorize( login, role, roster_name, 'roster_ops', extra)

        # Not allowed. Might be false
        if not permission:
            return False

        if permission not in (
                      PERM_ALLOW,
                      PERM_REQUIRE_DOCUMENTATION
                      ):
            return False

        # We got here. That means we're actually allowed to perform the
        # action on this URI. This means we'll allow the logging of this
        # action to the database
        rec = db.rosters.register_(session_id, roster_name, roster_data)

        # Return the result if successful
        return rec


    def roster_unregister(self, session_id, login, role, roster_name, extra):

        permission = self.authorize( login, role, roster_name, 'roster_ops', extra)

        # Not allowed. Might be false
        if not permission:
            return False

        if permission not in (
                      PERM_ALLOW,
                      PERM_REQUIRE_DOCUMENTATION
                      ):
            return False

        # We got here. That means we're actually allowed to perform the
        # action on this URI. This means we'll allow the logging of this
        # action to the database
        rec = db.rosters.unregister_(session_id, roster_name)

        # Return the result if successful
        return rec

    def roster_query(self, session_id, login, role, roster_name, extra):

        # We need the session session token to be able to tag the
        # session as reauthenticated
        cache_id = extra.get('cache_id')
        cookie_obj = db.get(cache_id,'cookie')

        if not cookie_obj:
            return False

        permission = self.authorize( login, role, roster_name, 'roster_query', extra)

        # Not allowed. Might be false
        if not permission:
            return False

        elif permission not in (
                      PERM_ALLOW,
                      PERM_REQUIRE_DOCUMENTATION
                      ):
            return False

        # By default we look for the roster name
        conditions = [ ['name', '=', roster_name] ]

        # Unless the role is trusted, we also force the search on the
        # role visibility
        # FIXME: need to handle the trusted status via the role record
        if role not in ('trust', 'trusted'):
            conditions.append(['or',[
                                      ['visibility', 'in', ['*', role]],
                                      ['visibility', 'has', '*'],
                                      ['visibility', 'has', role]
                                  ],
                            ])

        # We got here. That means we're actually allowed to perform the
        # action on this URI. This means we'll allow the query of this
        # roster_name
        results = db.query(
                    collection_type='rosters',
                    conditions=conditions,
                )

        return results

    #####################################################
    # URI Documentation
    #####################################################
    def system_document_set(self, 
              login,
              role,
              uri,
              action,
              options,
              data,
              extra=None,
          ):
        """ Used to register information related to a registered (or to be
            registered) URI.

            action: can be of register, call, publish, subscribe
            uri: uri path
            data: dict(
                        description="text"
                        owner="information about the uri manager"
                      )
        """
        permission = self.authorize( login, role, uri, action, options, extra )

        # Not allowed. Might be false
        if not permission:
            return False

        if permission not in (
                      PERM_ALLOW,
                      PERM_REQUIRE_DOCUMENTATION
                      ):
            return False

        # We got here. That means we're actually allowed to perform the
        # action on this URI. This means we'll allow the logging of this
        # action to the database
        match = data.get('match') or 'exact'
        db.uris.upsert_(
            action,
            match,
            uri,
            data
        )

        return True

    def system_document_get(self, match, uri, details=None):
        pass

    #####################################################
    # User Management
    #####################################################

    def user_get(self, login, yaml=False):
        """ Fetches information about a single user
        """
        user_obj = db.user_get(login)

        if user_obj and user_obj.source == AUTH_SOURCE_LOCAL:
            return user_obj.dict_(yaml)

        # If we don't initially get information, or the user is
        # ldap based, let's query ldap to discover or get more 
        # informaiton.
        ldap_user = ldap.user_get(login)
        if not ldap_user:
            if user_obj:
                return user_obj.dict_(yaml)
            else:
                return

        # If the user_rec doesn't already exist, let's create a new
        # stub entry for the ldap user.
        user_obj = user_obj or db.user_create({
                                    'login': login,
                                    'source': AUTH_SOURCE_LDAP,
                                    'role': DEFAULT_ROLE,
                                    'enabled': True
                                })
        user_rec = user_obj.dict_(yaml)

        # We overlay the ldap information on top of what
        # we store locally
        for k, v in ldap_user.items():
            # For enabled, we need both the local and
            # domain to say we are enabled
            if k == 'enabled':
                user_rec[k] = user_rec.get('enabled') and v
            else:
                user_rec[k] = v

        return user_rec


    def user_enable(self, login):
        """ Sets the data associated with the user to be enabled=True
        """
        db.users[login].update_({'enabled':True}).save_()

    def user_disable(self, login):
        """ Sets the data associated with the user to be enabled=False
        """
        db.users[login].update_({'enabled':False}).save_()

    #####################################################
    # Metadata handling
    #####################################################

    def user_metadata_get(self, login, key, yaml=False):
        """ Fetches a single entry by key
        """
        if yaml:
            return db.users[login].metadata[key].value_yaml
        else:
            return db.users[login].metadata[key].value

    def user_metadata_set(self, login, key, value, yaml=False):
        """ Sets a single entry by key
        """
        metadata_obj = db.users[login].metadata
        meta_obj = metadata_obj.get_(key)
        if yaml:
            value = yaml_loads(value)
        if meta_obj:
            return meta_obj.update_({'value':value}).save_().dict_(yaml)
        else:
            return metadata_obj.create_({
                          'key': key,
                          'value': value
                        }).dict_()

    def user_metadata_remove(self, login, key, yaml=False):
        """ Removes a single entry by key
        """
        meta_obj = db.users[login].metadata.get_(key)
        if meta_obj:
            meta_obj.delete_()


    #####################################################
    # Database Maintenance
    #####################################################

    def vacuum(self):
        db.vacuum_()

    def sync(self):
        """ This ensures that all the ldap records have been pulled into the local
            database.
        """
        # Get a list of users from the database
        user_lookup = {}
        for user_obj in db.users:
            user_lookup[user_obj.login] = user_obj

        # Let's get a list of users from ldap
        ldap_user_list = ldap.users()
        for user_data in ldap_user_list:
            login = user_data['login']

            ldap_data = {
                'name': user_data.get('name'),
                'email': user_data.get('email'),
                'upn': user_data.get('upn'),
                'enabled': user_data.get('enabled'),
            }

            # If the user doesn't already exist in the system we will go through
            # and add the database record for ourselves
            if login not in user_lookup:
                user_obj = db.users.create_({
                                    'login': login,
                                    'source': AUTH_SOURCE_LDAP,
                                    'role': DEFAULT_ROLE,
                                    **ldap_data
                                })

            # Update with LDAP info
            else:
                user_obj = user_lookup[login]
                changed = False
                for k, v in ldap_data.items():
                    if user_obj[k] == v:
                        continue
                    user_obj[k] = v
                    changed = True
                if changed:
                    user_obj.save_()



