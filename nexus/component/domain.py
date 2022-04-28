"""

This provides the core nexus domain related bindings. It handles things like:

- authentication
- authorization
- LDAP access
- ORM access to models like
  - User
  - Role
  - API Key
  - Cookies

So basically the core functionality that lets users/admins use and manage the system.

"""

from nexus.component.base import *

import time
import schedule
import traceback

from izaber import config

import nexus
from nexus.constants import PERM_ALLOW, PERM_REQUIRE_DOCUMENTATION, WAMP_LOCAL_REGISTRATION_PREFIX
from nexus.orm import *
from nexus.domain import *
from nexus.cron import cron
from nexus.log import log

from twisted.internet.defer import inlineCallbacks, DeferredList
from autobahn.wamp.exception import ApplicationError

def extract_peer(transport):
    # Get the peer address of the session. We'll get them via the following order
    # 1. x-real-ip
    # 2. x-forwarded-for (uses the first entry)
    # 3. peer (might be the IP of the proxy)
    if not transport:
        return 'unknown'

    http_headers = transport.get('http_headers_received',{})
    peer = None
    if http_headers:
        peer = http_headers.get( 'x-real-ip',
                  http_headers.get( 'x-forwarded-for' ) )
        if peer:
            peer = peer.split(',')[0].strip()
    if not peer and transport.get('peer'):
        peer = transport['peer'].split(':')[1]

    return peer or 'unknown'

SESSIONS = {}
REGISTRATIONS = {}

class DomainComponent(BaseComponent):
    last_sync = None

    #############################################################################
    # Session Tracking
    # See: https://github.com/wamp-proto/wamp-proto/blob/master/rfc/text/advanced/ap_session_meta_api.md
    #############################################################################
    @wamp_subscribe('wamp.session.on_join')
    def session_on_join(self, session_details, details):
        if not session_details:
            return
        if 'session' not in session_details:
            return

        session_id = session_details['session']
        SESSIONS.setdefault(session_id,{})\
                .update({
                    'details': session_details
                })

    @wamp_subscribe('wamp.session.on_leave')
    def session_on_leave(self, session_id, details):
        # Remove all roster entries for this ession
        controller.roster_unregister_session(session_id)

        # Remove from session cache if it's there
        if not session_id in SESSIONS:
            return
        del SESSIONS[session_id]

    #############################################################################
    # Authentication
    #############################################################################

    @wamp_register('.auth.authenticator')
    def authenticator(self, realm, authid, options, *args, **kwargs):
        """ Check against ZERP if the user is valid

            realm: configuration header (for kinda means application group)
            authid: login
            details: other stuff including the password
        """

        log.info(f"Authenticating '{authid}'")

        # If there's no ticket (password) provided we simply drop out
        password = options.get('ticket')
        if not password:
            log.warn(f"NOPASSWORD: Rejected {authid}")
            raise InvalidLoginPermissionError('Invalid Login')
            raise ApplicationError('com.izaber.wamp.error.invalidlogin','Invalid Login')

        # This authentication may have been assigned a Cookie
        # if so, we want to keep track of it
        try:
            cbtid = options['transport'].get('cbtid')
        except KeyError as ex:
            cbtid = None

        res = controller.login(authid, password, cbtid)
        if not res:
            log.warn(f"PASSWORDERROR: Rejected {authid}")
            raise InvalidLoginPermissionError('Invalid Login')

        cookie_obj = res['cookie_obj']
        transport = options.get('transport',{})
        cookie_obj.data['cbtid'] = transport.get('cbtid')
        cookie_obj.data['peer'] = extract_peer(transport)
        cookie_obj.data['cookie'] = options.get('cookie')
        cookie_obj.save_()

        # We want to session information if we can
        if options:
            session_id = options['session']
            SESSIONS[session_id] = {
                'options': options,
                'auth_res': res,
            }
        return res

    @wamp_register('.auth.authenticate')
    def authenticate(self, login, password, details):
        try:
            return bool(controller.authenticate(login, password))
        except Exception as ex:
            log.error(f"Couldn't authenticate {login} due to {ex}")
            return False

    #############################################################################
    # Authorization
    #############################################################################

    @wamp_register('.auth.authorizer')
    def authorizer(self, session, uri, action, options, **kwargs):
        """ Validates an action for a session to specific URIs 
        """
        auth_id = session['authid']
        auth_role = session['authrole']
        extra = session['authextra']

        try:
            permission = controller.authorize( auth_id, auth_role,
                                                uri, action, extra, options )

            # Not allowed. Might be false
            if not permission:
                return False

            # If the action requires documentation to be provided
            if permission == PERM_REQUIRE_DOCUMENTATION:
                msg = f"{action}://{uri} requires documentation in the database before {action} may be called"
                raise RequireDocumentationPermissionError(msg)

            # Allowed
            if permission == PERM_ALLOW:
                return {'allow': True, 'disclose': True}

            # Not allowed since we don't have elevated privs
            return False

        # Something exploded
        except ApplicationError as ex:
            raise

        except PermissionError as ex:
            raise

        except Exception as ex:
            tb = traceback.format_exc()
            log.error(f"Authorizer error for '{action}://{uri}': {ex} {tb}")
            return False

    def get_extra_from_details(self, details):
        """ Lookups up the extras data from details
        """
        session = SESSIONS.get(details.caller,{})
        if not session:
            return
        return session.get('details',{}).get('authextra')

    @wamp_register('.auth.reauthenticate')
    @wamp_register('auth.reauthenticate')
    @wamp_register('.system.reauthenticate', deprecated=True)
    def reauthenticate(self, password, details):
        """ If the password matches the current session's authid,
            adds the elevated privileges property to ths current session
        """
        authid = details.caller_authid
        log.info(f"Authenticating elevated {authid}")
        extra = self.get_extra_from_details(details)
        return controller.reauthenticate(authid, password, extra)

    @wamp_register('.auth.reauthenticate_expire')
    @wamp_register('auth.reauthenticate_expire')
    def reauthenticate_expire(self, details):
        """ Strips the elevated authentication status from the session
        """
        authid = details.caller_authid
        log.info(f"Removing elevated auth for '{authid}'")
        extra = self.get_extra_from_details(details)
        controller.reauthenticate_expire(extra)

    @wamp_register('.auth.is_reauthenticated')
    @wamp_register('auth.is_reauthenticated')
    @wamp_register('.system.is_reauthenticated', deprecated=True)
    def is_reauthenticated(self, details):
        """ Returns the amount of time elapsed since last authentication
        """
        extra = self.get_extra_from_details(details)
        return controller.reauthenticate_remaining(extra)

    @wamp_register('.auth.extend_reauthenticate')
    @wamp_register('auth.extend_reauthenticate')
    @wamp_register('.system.extend_reauthenticate', deprecated=True)
    def extend_reauthenticate(self, details):
        """ Updates the checkpoint from where the system will consider a session
            stale and strip it of elevated privileges
        """
        extra = self.get_extra_from_details(details)
        return controller.reauthenticate_touch(extra)

    @wamp_register('.auth.refresh_authorizer')
    @wamp_register('auth.refresh_authorizer')
    def reload(self, details):
        """ Request a reload of the database
        """
        controller.reload()

    #############################################################################
    # Database Maintenance
    #############################################################################

    def sync(self):
        """ Runs the process that syncs the database with ldap and other things
        """
        start_time = time.time()
        log.info(f"Running system sync")
        controller.sync()
        elapsed = time.time() - start_time
        log.info(f"System sync took {elapsed} seconds")

    @wamp_register('.system.sync')
    @wamp_register('system.sync')
    def system_sync(self, details=None):
        """ Runs the process that syncs the database with ldap and other things
        """
        self.sync()

    def vacuum(self):
        """ Runs the process that cleans up the database
        """
        start_time = time.time()
        log.info(f"Running system vacuum")

        # First we need to touch all NexusCookies records of all
        # sessions currently active
        for session_id, data in SESSIONS.items():
            extra = data.get('details',{}).get('authextra')
            cache_id = extra.get('cache_id')
            if not cache_id:
                continue

            try:
                cookie_obj = db.get(cache_id,'cookie')
            except Exception as ex:
                log.warn(f"cache_id {cache_id} didn't resolve to a cookie! <{ex}>")
                continue

            try:
                cookie_obj.touch_()
            except Exception as ex:
                log.warn(f"Unable to touch cookie {cache_id} <{ex}>")

        # Now we need to validate that all current roster entries are
        # actually alive by comparing the results against the session list
        for entry in db.rosters:
            if entry.session_id in SESSIONS:
                continue
            entry.delete_()

        # Let the control do the rest of the vacuuming across the system
        controller.vacuum()

        elapsed = time.time() - start_time
        log.info(f"System vacuum took {elapsed} seconds")

        return elapsed

    @wamp_register('.system.vacuum')
    @wamp_register('system.vacuum')
    def system_vacuum(self, details):
        """ Runs the process that cleans up the database
        """
        return self.vacuum()

    #############################################################################
    # LDAP
    #############################################################################

    @wamp_register('.ad.users')
    @wamp_register('ad.users')
    @wamp_register('.directory.users', deprecated=True)
    def ldap_users(self, details):
        users = []
        for entry in ldap.users_raw():
            users.append({
                    'attributes': entry,
                    'db': entry['dn']
                })
        return users

    @wamp_register('.ad.groups')
    @wamp_register('ad.groups')
    @wamp_register('.directory.groups', deprecated=True)
    def ldap_groups(self, details):
        return ldap.groups_raw()

    @wamp_register('.auth.whoami')
    @wamp_register('auth.whoami')
    def whoami(self, details):
        """ Returns information related to the current user
        """
        return {
            'authid': details.caller_authid,
            'role': details.caller_authrole,
        }

    #############################################################################
    # Registration Tracking
    # See: https://github.com/wamp-proto/wamp-proto/blob/master/rfc/text/advanced/ap_rpc_registration_meta_api.md
    #############################################################################

    @wamp_register('.system.document.set')
    @wamp_register('system.document.set')
    def system_document_set(self, action, uri, data, details=None):
        """ Used to register information related to a registered (or to be
            registered) URI.

            action: can be of register, call, publish, subscribe
            uri: uri path
            details: dict(
                        description="text"
                        contact="information about the uri manager"
                      )
        """

        # Find out if the user can access this uri
        session = SESSIONS.get(details.caller,{})
        if not session:
            return False

        # We ignore everything except register for now
        if action!= 'register':
            return False

        extra = session.get('details',{}).get('authextra',{})
        options = session.get('details',{}).get('options',{})
        try:
            return controller.system_document_set(
                            details.caller_authid,
                            details.caller_authrole,
                            uri, action, options, data, extra )

        # Something exploded
        except ApplicationError as ex:
            raise

        except Exception as ex:
            tb = traceback.format_exc()
            log.error(f"Authorized crashed for '{action}://{uri}': {ex} {tb}")
            return False


    @wamp_register('.system.document.get')
    @wamp_register('system.document.get')
    def system_document_get(self, match, uri, details=None):
        """ Used to register information related to a registered (or to be
            registered) URI.
        """
        pass

    @wamp_subscribe('wamp.registration.on_register')
    def registration_on_register(self, session_id, registration_id, details=None ):
        """ When we get a notification for a new registration, we want to log
            its existance in the database along with tracking metadata such as
            source and connection times
        """
        try:
            def on_register_data( reg_data ):
                # sess_data = {
                #    'id': 1979701189101083,
                #    'created': '2021-09-26T16:32:22.704Z',
                #    'uri': 'com.izaber.wamp.my.apikeys.delete',
                #    'match': 'exact',
                #    'invoke': 'single'
                # }

                # Start the new record off
                uri = reg_data['uri']
                match = reg_data['match']
                invoke = reg_data['invoke']

                # Get some information on the session if possible which allows us
                # to set information like where the connection last came from
                sess_rec = None
                peer = None
                authid = None
                if session_id and session_id in SESSIONS:
                    sess_rec = SESSIONS[session_id]
                    details = sess_rec.get('details',{})
                    peer = extract_peer(details.get('transport'))
                    authid = details.get('authid','')

                # Update the reference in the databse
                reg_rec = db.uris.upsert_(
                                'register',
                                match,
                                uri,
                                {
                                    'match': match,
                                    'invoke': invoke,
                                    'active': True,
                                    'create': reg_data['created'],
                                    'system': not sess_rec, # system/trusted have no info so we cheat
                                    'peer': peer,
                                    'authid': authid,
                                }
                            )

                REGISTRATIONS[registration_id] = reg_rec.key

            self.call('wamp.registration.get', registration_id)\
                .addCallback(on_register_data)

        except Exception as ex:
            log.error(f"ERROR in nexus' registration_on_register: {ex}")

    @wamp_subscribe('wamp.registration.on_unregister')
    def registration_on_unregister(self, session_id, registration_id, details=None ):
        """ We don't do anything right now since we don't actually get the session
            id most of the time
        """
        pass

    @wamp_subscribe('wamp.registration.on_delete')
    def registration_on_delete(self, session_id, registration_id, details=None ):
        """ This is invoked when the last session attached to this registration is removed
            effectively making the uri no longer valid. We hook this so we can note
            when the registration was last connected
        """
        try:
            # There is a good chance that the session_id is null since the
            # unregister may have triggered as of the result of a disconnect
            # We're not going to worry about it for now and care more about the
            # registration instead
            if not registration_id:
                return

            # Figure out our internal record for the registered URI
            key_hash = REGISTRATIONS.get(registration_id)
            reg_rec = db.uris[key_hash]

            # Mark this registration as dead
            reg_rec.active = False

            # Record the changes
            reg_rec.save_()
        except Exception as ex:
            log.error(f"ERROR in nexus' registration_on_delete: {ex}")


    #############################################################################
    # Subscription Tracking
    # See: https://github.com/wamp-proto/wamp-proto/blob/master/rfc/text/advanced/ap_pubsub_subscription_meta_api.md
    #############################################################################
    @wamp_subscribe('wamp.subscription.on_subscribe')
    def subscription_on_subscribe(self, session_id, subscription_id, options=None, details=None):
        pass

    @wamp_subscribe('wamp.subscription.on_delete')
    def subscription_on_delete(self, session_id, subscription_id, options=None, details=None):
        pass


    #############################################################################
    # Roster Management
    #############################################################################

    @wamp_register('.system.roster.register')
    @wamp_register('system.roster.register')
    def roster_register(self, roster_name, data, visibility=None, details=None):

        # Default the visibility
        if visibility is None:
            visibility = '*'

        # If the visibility is something like False or '', throw an error
        if not visibility:
            raise ValueError(f'visibility must be a format like `['*']`')

        extra = self.get_extra_from_details(details)
        reg_rec = controller.roster_register(
                    details.caller,
                    details.caller_authid,
                    details.caller_authrole,
                    roster_name,
                    {
                        'data': data,
                        'visibility': visibility,
                    },
                    extra
                )

        if not reg_rec:
            raise RequireRosterOpsPermissionError(f'Unable to add to roster "{roster_name}"')

        return reg_rec.dict_()

    @wamp_register('.system.roster.unregister')
    @wamp_register('system.roster.unregister')
    def roster_unregister(self, roster_name, details):
        extra = self.get_extra_from_details(details)
        controller.roster_unregister(
                    details.caller,
                    details.caller_authid,
                    details.caller_authrole,
                    roster_name,
                    extra
                )

        return True

    @wamp_register('.system.roster.query')
    @wamp_register('system.roster.query')
    def roster_query(self, roster_name, details):
        extra = self.get_extra_from_details(details)
        results = controller.roster_query(
                    details.caller,
                    details.caller_authid,
                    details.caller_authrole,
                    roster_name,
                    extra
                )

        if results == False:
            raise RequireRosterQueryPermissionError(f'Unable to query roster "{roster_name}"')

        hits = results['records']
        roster_list = []
        for result in hits:
            roster_list.append(result.dict_()['data'])

        return roster_list

    #############################################################################
    # ORM
    #############################################################################

    @wamp_register('.system.db.query')
    @wamp_register('system.db.query')
    def db_query(self, collection_type,
                       conditions,
                       fields=None,
                       sort=None,
                       limit=None,
                       page_index=0,
                       yaml=False,
                       details=None):
        """ Executes an ORM query on the database
        """
        login = details.caller_authid
        results = db.query_authorized(
                    login=login,
                    collection_type=collection_type,
                    conditions=conditions,
                    fields=fields,
                    sort=sort,
                    limit=limit,
                    page_index=page_index
                )

        if not results['hits']: return results

        hits = results['records']
        dict_records = []
        for record in hits:
            record_rec = record.dict_(yaml)
            dict_records.append(record_rec)
        results['records'] = dict_records

        return results

    @wamp_register('.system.db.create')
    @wamp_register('system.db.create')
    def db_create(self, parent_uuid, collection_attrib, data_rec, yaml=False, details=None):
        """ Executes an ORM create on the database
        """
        login = details.caller_authid
        record = db.create_authorized(
                    login=login,
                    parent_uid_b64=parent_uuid,
                    collection_attrib=collection_attrib,
                    data_rec=data_rec
                )
        return record.dict_(yaml)

    @wamp_register('.system.db.update')
    @wamp_register('system.db.update')
    def db_update(self, uid_b64s, data_rec, details=None):
        login = details.caller_authid
        record = db.update_authorized(
                    login=login,
                    uid_b64s=uid_b64s,
                    data_rec=data_rec
                )
        return True

    @wamp_register('.system.db.delete')
    @wamp_register('system.db.delete')
    def db_delete(self, uid_b64s, details=None):
        login = details.caller_authid
        record = db.delete_authorized(
                    login=login,
                    uid_b64s=uid_b64s,
                )
        return True

    @wamp_register('.system.db.upsert')
    @wamp_register('system.db.upsert')
    def db_upsert(self, parent_uuid, collection_attrib, data_rec, yaml=False, details=None):
        login = details.caller_authid
        record = db.upsert_authorized(
                    login=login,
                    parent_uid_b64=parent_uuid,
                    collection_attrib=collection_attrib,
                    data_rec=data_rec
                )
        return record.dict_(yaml)

    ##################################################
    # Personal calls for transitional purposes
    ##################################################

    def my_metadata_list(self, yaml=False, details=None):
        login = details.caller_authid

        # Generates a lookup of user metadata
        metadata = {}
        for meta_obj in db.users[login].metadata:
            meta_data = meta_obj.dict_(yaml)
            del meta_data['key']
            metadata[meta_obj.key] = meta_data

        return metadata

    @wamp_register('.my.metadata.get')
    @wamp_register('my.metadata.get')
    @wamp_register('.system.preference.get', deprecated=True)
    def my_metadata_get(self, key, yaml=False, details=None):
        login = details.caller_authid
        meta_obj = db.users[login].metadata.get_(key)
        if not meta_obj:
            return
        if yaml:
            return meta_obj.value_yaml
        return simplify(meta_obj.value)

    @wamp_register('.my.metadata.set')
    @wamp_register('my.metadata.set')
    @wamp_register('.system.preference.set', deprecated=True)
    def my_metadata_set(self, key, value, yaml=False, details=None):
        login = details.caller_authid
        if yaml:
            value = yaml_loads(value)

        user_obj = db.users.get_(login)
        if not user_obj:
            raise KeyError('Unknown user')

        try:
            meta_obj = user_obj.metadata[key].update_({'value': value}).save_()
        except KeyError:
            meta_obj = user_obj.metadata.create_({
                                'key': key,
                                'value': value
                              })

        if yaml:
            return meta_obj.value_yaml
        else:
            return simplify(meta_obj.value)

    @wamp_register('.my.metadata.delete')
    @wamp_register('my.metadata.delete')
    def my_metadata_delete(self, key, details):
        login = details.caller_authid
        meta_obj = db.users[login].metadata.get_(key)
        if meta_obj:
            meta_obj.delete_()

    @wamp_register('.my.apikeys.list')
    @wamp_register('my.apikeys.list')
    def my_apikeys_list(self, details):
        login = details.caller_authid
        apikey_list = []
        for apikey_obj in db.users[login].apikeys:
            apikey_list.append(apikey_obj.dict_())
        return apikey_list

    @wamp_register('.my.apikeys.create')
    @wamp_register('my.apikeys.create')
    def my_apikeys_create(self, data_rec=None, details=None):
        login = details.caller_authid
        user_obj = db.users[login]
        return self.db_create(
                        user_obj.uuid,
                        'apikeys',
                        data_rec or {},
                        details=details)

    @wamp_register('.my.apikeys.delete')
    @wamp_register('my.apikeys.delete')
    def my_apikeys_delete(self, uuid_b64, details):
        return self.db_delete( [uuid_b64], details=details)

    #############################################################################
    # Cron tasks
    #############################################################################

    def cron_vacuum(self):
        """ Runs the process that cleans up the database
        """
        self.vacuum()

    def cron_sync(self):
        """ Runs the process that syncs the database with ldap and other things
        """
        self.sync()

    #############################################################################
    # OnJoining the crossbar router
    #############################################################################

    @inlineCallbacks
    def onJoin(self, details):

        for res in super().onJoin(details):
            yield res

        SESSIONS.clear()

        # We setup a scheduler to run every 5 minutes to clean up the database
        # and do other periodic tasks. This just schedules, the actual running of
        # the code gets done in the nexus.cron.Cron object which executes on its
        # own separate thread.
        try:
            schedule.clear('component')

            # If the configuration is setup to skip the sync/vacuum
            # nexus:
            #    db:
            #      skip_vacuum: True
            #      skip_sync: True
            nexus_config = config.get('nexus',{})
            if not nexus_config.get('skip_sync'):
                self.sync()
            if not nexus_config.get('skip_vacuum'):
                self.vacuum()

            # Then schedule it
            schedule.every(10).minutes.do(self.cron_vacuum).tag('component')
            schedule.every(30).minutes.do(self.cron_sync).tag('component')
        except Exception as ex:
            print("-----------------------------------------------")
            print("EX:", ex)
            print("-----------------------------------------------")


