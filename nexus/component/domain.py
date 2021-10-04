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
import hashlib

from izaber import initialize, config

from nexus.constants import PERM_ALLOW, WAMP_LOCAL_REGISTRATION_PREFIX
from nexus.orm import *
from nexus.domain import *
from nexus.cron import cron

from twisted.internet.defer import inlineCallbacks, DeferredList
from autobahn.wamp.exception import ApplicationError

# FIXME: Eventually this should be a part of the role record
def is_trusted(details):
    if details.caller_authrole in('trusted','trust'):
        return True
    return False

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

        session_id = session_details['session']
        SESSIONS.setdefault(session_id,{})\
                .update({
                    'details': session_details
                })

    @wamp_subscribe('wamp.session.on_leave')
    def session_on_leave(self, session_id, details):
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
        try: # attempt login
            self.log.info(f"Authenticating '{authid}'")

            # If there's no ticket (password) provided we simply drop out
            password = options.get('ticket')
            if not password:
                self.log.warn(f"NOPASSWORD: Rejected {authid}")
                raise Exception('Invalid Login')

            # This authentication may have been assigned a Cookie
            # if so, we want to keep track of it
            try:
                cbtid = options['transport'].get('cbtid')
            except KeyError as ex:
                cbtid = None

            res = controller.login(authid, password, cbtid)
            if not res:
                self.log.warn(f"PASSWORDERROR: Rejected {authid}")
                raise Exception('Invalid Login')

            cookie_obj = res['cookie_obj']
            transport = options.get('transport',{})
            cookie_obj.data['cbtid'] = transport.get('cbtid')
            cookie_obj.data['peer'] = transport.get('peer')
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

        except Exception as ex:
            self.log.debug(f"Auth Fail for {authid} because '{ex}' <{type(ex)}>")
            # This is helpful when during development we're breaking stuff
            #traceback.print_exc()

        return False

    @wamp_register('.auth.authenticate')
    def authenticate(self, login, password, details):
        try:
            return bool(controller.authenticate(login, password))
        except Exception as ex:
            self.log.error(f"Couldn't authenticate {login} due to {ex}")
            return False

    #############################################################################
    # Authorization
    #############################################################################

    @wamp_register('.auth.authorizer')
    def authorizer(self, session, uri, action, *args, options=None, **kwargs):
        """ Validates an action for a session to specific URIs 
        """
        auth_id = session['authid']
        auth_role = session['authrole']
        extra = session['authextra']

        permission = controller.authorize( auth_id, auth_role,
                                            uri, action, extra )

        # Not allowed. Might be false
        if not permission:
            return False

        # Allowed
        if permission == PERM_ALLOW:
            return {'allow': True, 'disclose': True}

        # Not allowed since we don't have elevated privs
        return False

    def get_extra_from_details(self, details):
        """ Lookups up the extras data from details
        """
        session = SESSIONS.get(details.caller,{})
        if not session:
            return
        return session.get('details',{}).get('authextra')

    @wamp_register('.auth.reauthenticate')
    @wamp_register('.system.reauthenticate', deprecated=True)
    def reauthenticate(self, password, details):
        """ If the password matches the current session's authid,
            adds the elevated privileges property to ths current session
        """
        authid = details.caller_authid
        self.log.info(f"Authenticating elevated {authid}")
        extra = self.get_extra_from_details(details)
        return controller.reauthenticate(authid, password, extra)

    @wamp_register('.auth.reauthenticate_expire')
    def reauthenticate_expire(self, details):
        """ Strips the elevated authentication status from the session
        """
        authid = details.caller_authid
        self.log.info(f"Removing elevated auth for '{authid}'")
        extra = self.get_extra_from_details(details)
        controller.reauthenticate_expire(extra)

    @wamp_register('.auth.is_reauthenticated')
    @wamp_register('.system.is_reauthenticated', deprecated=True)
    def is_reauthenticated(self, details):
        """ Returns the amount of time elapsed since last authentication
        """
        extra = self.get_extra_from_details(details)
        return controller.reauthenticate_remaining(extra)

    @wamp_register('.auth.extend_reauthenticate')
    @wamp_register('.system.extend_reauthenticate', deprecated=True)
    def extend_reauthenticate(self, details):
        """ Updates the checkpoint from where the system will consider a session
            stale and strip it of elevated privileges
        """
        extra = self.get_extra_from_details(details)
        return controller.reauthenticate_touch(extra)

    @wamp_register('.auth.refresh_authorizer')
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
        self.log.info(f"Running system sync")
        controller.sync()
        elapsed = time.time() - start_time
        self.log.info(f"System sync took {elapsed} seconds")

    @wamp_register('.system.sync')
    def system_sync(self, details=None):
        """ Runs the process that syncs the database with ldap and other things
        """
        self.sync()

    def vacuum(self):
        """ Runs the process that cleans up the database
        """
        start_time = time.time()
        self.log.info(f"Running system vacuum")

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
                self.log.warn(f"cache_id {cache_id} didn't resolve to a cookie! <{ex}>")
                continue

            try:
                cookie_obj.touch_()
            except Exception as ex:
                self.log.warn(f"Unable to touch cookie {cache_id} <{ex}>")

        controller.vacuum()

        elapsed = time.time() - start_time
        self.log.info(f"System vacuum took {elapsed} seconds")

    @wamp_register('.system.vacuum')
    def system_vacuum(self, details):
        """ Runs the process that cleans up the database
        """
        self.vacuum()

    #############################################################################
    # LDAP
    #############################################################################

    @wamp_register('.ad.users')
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
    @wamp_register('.directory.groups', deprecated=True)
    def ldap_groups(self, details):
        return ldap.groups_raw()

    @wamp_register('.auth.whoami')
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

                # We make a key of the record mixing both uri and
                # match type
                key_hash = hashlib.md5(f"{match}:{uri}".encode("utf-8")).hexdigest()

                self.log.warn(f"REG: {registration_id}:{key_hash}")

                # Get some information on the session if possible which allows us
                # to set information like where the connection last came from
                sess_rec = None
                peer = None
                authid = None
                if session_id and session_id in SESSIONS:
                    sess_rec = SESSIONS[session_id]
                    details = sess_rec.get('details',{})
                    peer = details.get('transport',{}).get('peer','')
                    authid = details.get('authid','')

                # Does this already exist in the database?
                REGISTRATIONS[registration_id] = key_hash

                reg_rec = db.registrations.get_(key_hash)
                if reg_rec:
                    reg_rec.active = True
                    reg_rec.create = reg_data['created']
                    reg_rec.system = not sess_rec # system/trusted have no info so we cheat
                    reg_rec.peer = peer
                    reg_rec.authid = authid
                    reg_rec.save_()

                else:
                    registration_rec = {
                        'key': key_hash,
                        'uri': uri,
                        'match': match,
                        'invoke': invoke,
                        'active': True,
                        'create': reg_data['created'],
                        'system': not sess_rec, # system/trusted have no info so we cheat
                        'peer': peer,
                        'authid': authid,
                    }
                    reg_rec = db.registrations.create_(registration_rec)
                self.log.warn(f"REGREC: {reg_rec}")

            self.call('wamp.registration.get', registration_id)\
                .addCallback(on_register_data)

        except Exception as ex:
            self.log.error(f"ERROR in nexus' registration_on_register: {ex}")

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
            self.log.warn(f"REGDEL: {registration_id}:{key_hash}")
            reg_rec = db.registrations[key_hash]

            # Mark this registration as dead
            reg_rec.active = False

            # Record the changes
            reg_rec.save_()
        except Exception as ex:
            self.log.error(f"ERROR in nexus' registration_on_delete: {ex}")


    #############################################################################
    # Subscription Tracking
    # See: https://github.com/wamp-proto/wamp-proto/blob/master/rfc/text/advanced/ap_pubsub_subscription_meta_api.md
    #############################################################################
    @wamp_subscribe('wamp.subscription.on_subscribe')
    def subscription_on_subscribe(self, session_id, options=None, details=None):
        pass

    @wamp_subscribe('wamp.subscription.on_delete')
    def subscription_on_delete(self, session_id, details):
        pass

    #############################################################################
    # ORM
    #############################################################################

    @wamp_register('.system.db.query')
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
    def db_update(self, uid_b64s, data_rec, details=None):
        login = details.caller_authid
        record = db.update_authorized(
                    login=login,
                    uid_b64s=uid_b64s,
                    data_rec=data_rec
                )
        return True

    @wamp_register('.system.db.delete')
    def db_delete(self, uid_b64s, details=None):
        login = details.caller_authid
        record = db.delete_authorized(
                    login=login,
                    uid_b64s=uid_b64s,
                )
        return True

    @wamp_register('.system.db.upsert')
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
    def my_metadata_delete(self, key, details):
        login = details.caller_authid
        meta_obj = db.users[login].metadata.get_(key)
        if meta_obj:
            meta_obj.delete_()

    @wamp_register('.my.apikeys.list')
    def my_apikeys_list(self, details):
        login = details.caller_authid
        apikey_list = []
        for apikey_obj in db.users[login].apikeys:
            apikey_list.append(apikey_obj.dict_())
        return apikey_list

    @wamp_register('.my.apikeys.create')
    def my_apikeys_create(self, data_rec=None, details=None):
        login = details.caller_authid
        user_obj = db.users[login]
        return self.db_create(
                        user_obj.uuid,
                        'apikeys',
                        data_rec or {},
                        details=details)

    @wamp_register('.my.apikeys.delete')
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

            # Do it once before we start
            self.sync()
            self.vacuum()

            # Then schedule it
            schedule.every(10).minutes.do(self.cron_vacuum).tag('component')
            schedule.every(30).minutes.do(self.cron_sync).tag('component')
        except Exception as ex:
            print("-----------------------------------------------")
            print("EX:", ex)
            print("-----------------------------------------------")

initialize('nexus')
