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

import os
import sys
import time
import schedule
import traceback

from izaber import config, initialize

import nexus
from nexus.constants import PERM_ALLOW, PERM_REQUIRE_DOCUMENTATION, WAMP_LOCAL_REGISTRATION_PREFIX
from nexus.orm import *
from nexus.domain import *
from nexus.cron import cron
from nexus.log import log

from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks, DeferredList
from autobahn.wamp.exception import ApplicationError

def extract_peer_data(details):
    # Gets two things:
    #   (1) peer address of the session. We'll get them via the following order
    #        1. x-real-ip
    #        2. x-forwarded-for (uses the first entry)
    #        3. peer (might be the IP of the proxy)
    #   (2) the WAMP agent for this session
    #

    transport = details.get('transport',{})

    # (1) Get the peer_address
    peer = None
    if transport:
        http_headers = transport.get('http_headers_received',{})
        if http_headers:
            peer = http_headers.get( 'x-real-ip',
                      http_headers.get( 'x-forwarded-for' ) )
            if peer and ',' in peer:
                peer = peer.split(',')[0].strip()

        if not peer and transport.get('peer'):
            peer = transport['peer']
            # peer can also be `unix` which doesn't have an associated
            # IP breakdown
            if ':' in peer:
                peer = peer.split(':')[1]

    # (2) get the agent and append the user-agent if available
    agent = details.get('authextra',{}).get('authagent','-')
    user_agent = transport.get('http_headers_received',{})\
                          .get('user-agent','')
    if user_agent:
        agent += f"[{user_agent}]"

    return peer or 'unknown', agent or 'unknown'

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
        self.session_delete(session_id)

    def session_delete(self, session_id):
        # Remove all roster entries for this ession
        controller.roster_unregister_session(session_id)

        # Remove from session cache if it's there
        if not session_id in SESSIONS:
            return
        del SESSIONS[session_id]


    #############################################################################
    # Metadata extraction
    #############################################################################
    @wamp_register('.system.subscribed')
    @wamp_register('system.subscribed')
    @inlineCallbacks
    def system_subscribed(self, details):
        """ Returns a list of all known subscriptions on the system along with
            any available metadata on the subscribers. Note that privileged
            sessions do not return information (they get blocked from
            wamp.session.get lower down) so subscriptions from trusted level
            connections will not yield any data.
        """

        sessions = {}
        subscriptions = {}

        res = yield self.call('wamp.subscription.list')
        for sub_type, sub_ids in res.items():
            subscriptions_for_type = subscriptions.setdefault(sub_type, {})

            for sub_id in sub_ids:
                info = yield self.call('wamp.subscription.get', sub_id)
                subscriptions_for_type[sub_id] = info

                subscribed = info['sessions'] = {}
                session_ids = yield self.call('wamp.subscription.list_subscribers', sub_id)
                for session_id in session_ids:

                    # Load information about the session should we not have any info
                    if session_id not in sessions:
                        try:
                            session = yield self.call('wamp.session.get', session_id)
                            if not session:
                                continue
                            session['peer'] = extract_peer_data(session['transport'])
                        except Exception as ex:
                            log.warning(f"!!!! GOT HERE WITH {ex}")
                            session = None
                        sessions[session_id] = session

                    # No good session info? Skip
                    session = sessions[session_id]
                    if not session:
                        continue

                    subscribed[f"{authid}@{peer}"] = session

        return subscriptions

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

        peer, agent = extract_peer_data(options)

        log.info(f"Authenticating '{authid}' from {peer}<{agent}>")

        # If there's no ticket (password) provided we simply drop out
        password = options.get('ticket')
        if not password:
            log.warning(f"NOPASSWORD: Rejected {authid} from {peer}<{agent}> with not ticket")
            raise InvalidLoginPermissionError('Invalid Login')

        # This authentication may have been assigned a Cookie
        # if so, we want to keep track of it
        try:
            cbtid = options['transport'].get('cbtid')
        except KeyError as ex:
            cbtid = None

        # Hand over authentication to the main nexus controller.
        # Just in case we receive some strange exceptions, we'll just:
        # 1. wrap the call then report the exception in the logs
        # 2. tell the user that had problems enough information to suggest
        #      that it wasn't them and give them a way to look into it more
        try:
            res = controller.login(authid, password, cbtid)
        except Exception as ex:
            log.error(f"INTERNALERROR: Rejected '{authid}' from {peer}<{agent}> due to <{ex}>")
            raise ApplicationError("Internal Error. Please contact sysadmin to review logs")

        if not res:
            log.warning(f"PASSWORDERROR: Rejected '{authid}' from {peer}<{agent}>")
            raise InvalidLoginPermissionError('Invalid Login')

        cookie_obj = res['cookie_obj']
        transport = options.get('transport',{})
        cookie_obj.data['cbtid'] = transport.get('cbtid')
        cookie_obj.data['peer'],  cookie_obj.data['agent'] = extract_peer_data(options)
        cookie_obj.data['cookie'] = options.get('cookie')
        cookie_obj.save_()

        # We want to session information if we can
        if options:
            session_id = options['session']
            SESSIONS[session_id] = {
                'options': options,
                'auth_res': res,
            }

        if res:
            log.info(f"Login success for '{authid}' from {peer}<{agent}>")
        return res

    @wamp_register('.auth.authenticate')
    def authenticate(self, login, password, details):
        try:
            return bool(controller.authenticate(login, password))
        except Exception as ex:
            peer, agent = extract_peer_data(options)
            log.error(f"Couldn't authenticate '{login}' from {peer}<{agent}> due to <{ex}>")
            return False

    #############################################################################
    # Authorization
    #############################################################################

    @wamp_register('.auth.authorizer')
    def authorizer(self, session, uri, action, options, **kwargs):
        """ Validates an action for a session to specific URIs 
        """
        authid = session['authid']
        auth_role = session['authrole']
        extra = session['authextra']

        try:
            permission = controller.authorize( authid, auth_role,
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
            log.error(f"Authorizer error for {authid}<{auth_role}> '{action}://{uri}': <{ex}> {tb}")
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
        log.info(f"System sync took {elapsed:0.02f} seconds")

    @wamp_register('.system.sync')
    @wamp_register('system.sync')
    def system_sync(self, details=None):
        """ Runs the process that syncs the database with ldap and other things
        """
        self.sync()

    @inlineCallbacks
    def _vacuum_otps(self):
        # Get a list of currently active otp
        try:
            start_time = time.time()
            log.info(f"Running OTP vacuum")

            db.users.vacuum_()

            elapsed = time.time() - start_time
            log.info(f"OTP vacuum took {elapsed:0.04f} seconds")

        except Exception as ex:
            log.error(f"Vacuum Sessions Exception! <{ex}>")
        yield True

    @wamp_register('.system.vacuum.otps')
    @wamp_register('system.vacuum.otps')
    def vacuum_otps(self):
        return self._vacuum_otps()

    def _vacuum_sessions(self, session_ids):
        start_time = time.time()
        log.info(f"Running session vacuum")

        # First we need to touch all NexusCookies records of all
        # sessions currently active
        for session_id, data in list(SESSIONS.items()):
            extra = data.get('details',{}).get('authextra')

            # Check if the session we're tracking is actually active
            if session_id not in session_ids:
                self.session_delete(session_id)
                continue

            # Internal component sessions do not have a cache_id so we
            # just go ahead and skip it
            cache_id = extra.get('cache_id')
            if not cache_id:
                continue

            try:
                cookie_obj = db.get(cache_id,'cookie')
            except Exception as ex:
                log.warning(f"cache_id {cache_id} didn't resolve to a cookie! <{ex}>")
                continue

            # We need to ensure that we actually have a cookie object
            if not cookie_obj:
                continue

            try:
                cookie_obj.touch_()
            except Exception as ex:
                log.warning(f"Unable to touch cookie {cache_id} <{ex}>")

        # Now we need to validate that all current roster entries are
        # actually alive by comparing the results against the session list
        for entry in db.rosters:
            if entry.session_id in SESSIONS:
                continue
            entry.delete_()

        elapsed = time.time() - start_time
        log.info(f"Session vacuum took {elapsed:0.04f} seconds")

    def vacuum_sessions(self):
        # Get a list of currently active sessions
        try:
            def errHandler(failure):
                log.error(f"Vacuum Sessions Failed because: {failure}")
            deferred = self.call('wamp.session.list')
            deferred.addCallback(self._vacuum_sessions)
            deferred.addErrback(errHandler)
        except Exception as ex:
            log.error(f"Vacuum Sessions Exception! <{ex}>")
        return True

    @wamp_register('.system.vacuum.sessions')
    @wamp_register('system.vacuum.sessions')
    def system_vacuum_sessions(self, details):
        """ Runs the process that clears out the sessions
        """
        self.vacuum_sessions()
        return True

    @inlineCallbacks
    def _handle_alerts(self, details=None):
        """ Scans through the pending disconnect list for any entires that require
            notification
        """
        try:
            # Do the alerts scan/polling routine
            db.uris.scan_for_disconnect_timeouts_()

            # Get get all the pending alerts if any to publish to the
            # right channel
            alerts = db.uris.receive_alerts_()
            for warning_type, duration, reg_rec in alerts:
                notification_message = reg_rec.dict_()
                yield self.publish('system.event.warning.registration',
                          warning_type,
                          duration,
                          notification_message
                      )
        except Exception as ex:
                tb = traceback.format_exc()
                log.error(f"Unable to process alerts because <{ex}> {tb}")
        yield True

    @wamp_register('.systems.handle.alerts')
    @wamp_register('systems.handle.alerts')
    def handle_alerts(self, details=None):
        return self._handle_alerts(details)


    @wamp_register('.system.vacuum.registrations')
    @wamp_register('system.vacuum.registrations')
    @inlineCallbacks
    def vacuum_registrations(self, details=None):
        """ Force-syncronizes the registrations status to the database to ensure that
            anything that might have desyncronized will have been addressed
        """
        start_time = time.time()
        log.info(f"Running registrations vacuum")

        try:
            # First we get a list of all the existing URIs in the database that are marked
            # active
            inactive_uris = {}
            for reg_rec in db.uris:
                if reg_rec.action != 'register':
                    continue
                inactive_uris[reg_rec.key] = reg_rec

            # Now get a list of all registrations that are actually active
            registrations = yield self.call('wamp.registration.list')
            for match, registration_ids in registrations.items():
                for registration_id in registration_ids:
                    try:
                        reg_data = None
                        uri_key = REGISTRATIONS.get(registration_id)
                        if not uri_key:
                            reg_data = yield self.call('wamp.registration.get', registration_id)
                            uri_key = db.uris.generate_key_('register', match, reg_data['uri'])
                            REGISTRATIONS[registration_id] = uri_key

                        # We expect an active URI to be in the active uris list
                        # so we'll remove it
                        if uri_key in inactive_uris:
                            del inactive_uris[uri_key]

                        # This is for the weird situation where a known active uri
                        # is actually *not* in the active uri list. we'll force the
                        # uri to be added
                        else:

                            # This is unlikely to be fired but just in case, since we need the information
                            # related to the registration, we'll acquire it. There is a strange instance where the
                            # entry will be empty when we're dealing with a system registration
                            if not reg_data:
                                reg_data = yield self.call('wamp.registration.get', registration_id)

                            session_ids = yield self.call('wamp.registration.list_callees', registration_id)
                            for session_id in session_ids:

                                sess_rec = None

                                # Get some information on the session if possible which allows us
                                # to set information like where the connection last came from
                                sess_rec = None
                                peer = None
                                authid = None
                                if session_id and session_id in SESSIONS:
                                    sess_rec = SESSIONS[session_id]
                                    details = sess_rec.get('details',{})
                                    peer, agent = extract_peer_data(details)
                                    authid = details.get('authid','')

                                # Update the reference in the databse
                                reg_rec = db.uris.upsert_registered_(
                                                match,
                                                reg_data['uri'],
                                                {
                                                    'match': match,
                                                    'invoke': reg_data['invoke'],
                                                    'create': reg_data['created'],
                                                    'system': not sess_rec, # system/trusted have no info so we cheat
                                                    'authid': authid,
                                                    'peer': peer,
                                                    'session_id': session_id,
                                                }
                                            )

                                REGISTRATIONS[registration_id] = reg_rec.key

                    except Exception as ex:
                        log.warn(f"Error getting information about a registration: <{type(ex)}>{ex}")

            # Mark registrations inactive for those URIs that are discovered inactive
            for uri_key, reg_rec in inactive_uris.items():
                reg_rec.mark_unregistered_()

            # Go through and reap any zombie URIs
            reaped_uris = db.uris.scan_for_zombie_reaps_()
            for reap_overdue, reap_uri in reaped_uris:
                notification_message = reap_uri.dict_()
                yield self.publish('system.event.warning.registration',
                          'zombie_reap',
                          reap_overdue,
                          notification_message
                      )

        except Exception as ex:
            tb = traceback.format_exc()
            log.error(f"Vacuum Registrations Exception! <{ex}> {tb}")

        elapsed = time.time() - start_time
        log.info(f"Registration vacuum took {elapsed:0.04f} seconds")

        return True

    def vacuum(self):
        """ Runs the process that cleans up the database
        """
        # Let the control do the rest of the vacuuming across the system
        # Running controller.vacuum is quite slow and if it's done without
        # wrapping it into a thread, it will block other requests from going 
        # through. We do this so that we can both vacuum and service user
        # requests at the same time. In the future, it may make sense to
        # wrap this into something that puts it into a separate subprocess
        def slow_vacuum():
            # Now that we're in the child process, we can start doing the long run process
            start_time = time.time()
            log.info(f"Running system vacuum")

            # While this is pretty quick to run, since we can, we'll run it
            # within a separate thread
            self.vacuum_sessions()

            # This full vacuum is actually slow where it goes through all the
            # stuff like UUID matching and such
            log.info(f"Running slow part of vacuum")
            controller.vacuum()
            elapsed = time.time() - start_time

            # We also want to run through and clean out what URIs are registered
            # as well as which ones are not
            log.info("Running registrations vacuum")
            self.vacuum_registrations()

            log.info(f"System vacuum took {elapsed:0.02f} seconds")

        threads.deferToThread(slow_vacuum)

    @wamp_register('.system.vacuum')
    @wamp_register('system.vacuum')
    def system_vacuum(self, details):
        """ Runs the process that cleans up the database
        """
        self.vacuum()
        return True

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
            log.error(f"Authorized crashed for '{action}://{uri}': <{ex}> {tb}")
            return False

    @wamp_register('.system.document.get')
    @wamp_register('system.document.get')
    def system_document_get(self, match, uri, details=None):
        """ Used to register information related to a registered (or to be
            registered) URI.
        """
        pass

    @wamp_subscribe('wamp.registration.on_register')
    @inlineCallbacks
    def registration_on_register(self, session_id, registration_id, details=None ):
        """ When we get a notification for a new registration, we want to log
            its existance in the database along with tracking metadata such as
            source and connection times
        """
        try:

            reg_data = yield self.call('wamp.registration.get', registration_id)

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
                peer, agent = extract_peer_data(details)
                authid = details.get('authid','')

            # Update the reference in the databse
            reg_rec = db.uris.upsert_registered_(
                            match,
                            uri,
                            {
                                'match': match,
                                'invoke': invoke,
                                'create': reg_data['created'],
                                'system': not sess_rec, # system/trusted have no info so we cheat
                                'authid': authid,
                                'peer': peer,
                                'session_id': session_id,
                            },
                            force=True
                        )

            # Let's submit a log message about a registration coming online
            log.info(f"REG {reg_rec.match}://{reg_rec.uri} from {reg_rec.authid}@{reg_rec.peer}")

            REGISTRATIONS[registration_id] = reg_rec.key

        except Exception as ex:
            log.error(f"ERROR in nexus' registration_on_register: <{ex}>")

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

            # Figure out our internal record for the registered URI then
            # mark it unregistered
            key_hash = REGISTRATIONS.get(registration_id)
            if not key_hash:
                return

            reg_rec = db.uris.get_(key_hash)
            if not reg_rec:
                return

            # Let's submit a log message about the loss of the registration if we've noticed
            # that we're switching states
            log.info(f"REGLOST {reg_rec.match}://{reg_rec.uri} from {reg_rec.authid}@{reg_rec.peer}")

            # We force this since we want to ensure proper recording of the disconnect
            reg_rec.mark_unregistered_(force=True)

        except Exception as ex:
            log.error(f"ERROR in nexus' registration_on_delete: <{ex}>")


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

    @wamp_register('.system.db.stats')
    @wamp_register('system.db.stats')
    def db_stats(self, details=None, **kwargs):
        stats = db.stats(**kwargs)
        return stats

    @wamp_register('.system.db.bulk_unload')
    @wamp_register('system.db.bulk_unload')
    def db_bulk_unload(self, nexus_type, details=None):
        db.bulk_unload(nexus_type)
        return True

    ##################################################
    # Personal calls for transitional purposes
    ##################################################

    @wamp_register('.my.metadata.list')
    @wamp_register('my.metadata.list')
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
    # One-Time-Password OTP tasks
    #############################################################################

    @wamp_register('.my.otp.list')
    @wamp_register('my.otp.list')
    def my_otp_list(self, details):
        login = details.caller_authid
        otp_list = []
        for otp_obj in db.users[login].otp:
            otp_list.append(otp_obj.dict_())
        return otp_list

    @wamp_register('.my.otp.create')
    @wamp_register('my.otp.create')
    def my_otp_create(self, details=None):
        # Find out if the user can access this uri
        session = SESSIONS.get(details.caller,{})
        if not session:
            return False

        # Find out who is calling
        login = details.caller_authid
        user_obj = db.users[login]
        peer, agent = extract_peer_data(session.get('details',{}))
        data_rec = {'origin': f"{login}@{peer}"}
        return self.db_create(
                        user_obj.uuid,
                        'otps',
                        data_rec,
                        details=details)

    @wamp_register('.my.otp.delete')
    @wamp_register('my.otp.delete')
    def my_otp_delete(self, uuid_b64, details):
        return self.db_delete( [uuid_b64], details=details)

    # For trusted users we can create OTP entries for others users

    @wamp_register('.system.otp.list')
    @wamp_register('system.otp.list')
    def system_otp_list(self, login, details):
        otp_list = []
        for otp_obj in db.users[login].otp:
            otp_list.append(otp_obj.dict_())
        return otp_list

    @wamp_register('.system.otp.create')
    @wamp_register('system.otp.create')
    def system_otp_create(self, login, data_rec=None, details=None):
        # Find out if the user can access this uri
        session = SESSIONS.get(details.caller,{})
        if not session:
            return False

        user_obj = db.users[login]
        if data_rec is None:
            data_rec = {}

        peer, agent = extract_peer_data(session.get('details',{}))
        data_rec['origin'] = f"{details.caller_authid}@{peer} created token for {login}"
        return self.db_create(
                        user_obj.uuid,
                        'otps',
                        data_rec,
                        details=details)

    @wamp_register('.system.otp.delete')
    @wamp_register('system.otp.delete')
    def system_otp_delete(self, uuid_b64, details):
        return self.db_delete( [uuid_b64], details=details)

    #############################################################################
    # Cron tasks
    #############################################################################

    def cron_vacuum_otps(self):
        """ Runs the process that removes old OTP entries
        """
        self.vacuum_otps()

    def cron_vacuum_sessions(self):
        """ Runs the process that removes old sessions
        """
        self.vacuum_sessions()

    def cron_vacuum_registrations(self):
        """ Runs the process that removes old sessions
        """
        self.vacuum_registrations()

    def cron_vacuum(self):
        """ Runs the process that cleans up the database
        """
        self.vacuum()

    def cron_sync(self):
        """ Runs the process that syncs the database with ldap and other things
        """
        self.sync()

    def cron_handle_alerts(self):
        """ Scan the URI action
        """
        def handle_alerts():
            self.handle_alerts()
        threads.deferToThread(handle_alerts)

    #############################################################################
    # OnJoining the crossbar router
    #############################################################################

    @inlineCallbacks
    def onJoin(self, details):

        # Wipe old sessions away if anything is here
        for session_id, data in list(SESSIONS.items()):
            self.session_delete(session_id)
        SESSIONS.clear()
        log.info(f"Cleared old sessions")

        # Load in the existing sessions
        sess_ids = yield self.call('wamp.session.list')
        for sess_id in sess_ids:
            sess_rec = yield self.call('wamp.session.get', sess_id)

        # Then do the registrations
        for value in super().onJoin(details):
            yield value

        # We setup a scheduler to run every 2 minutes to clean up the database
        # and do other periodic tasks. This just schedules, the actual running of
        # the code gets done in the nexus.cron.Cron object which executes on its
        # own separate thread.
        try:
            schedule.clear('component')

            # By default nexus does not do a vacuum and sync upon start.
            #
            # - vacuum ensures we don't have crufy UUID and so on around
            # - sync pulls all users from ldap into the system
            #
            # Usually this isn't an issue and UUID reindexing can take a
            # horrible amount of time. Best bet is to invoke reindex from
            # the `nexus` CLI tool and sync can be run normally from
            # the cron job
            #
            # nexus:
            #    db:
            #      startup_vacuum: True
            #      startup_sync: True
            nexus_config = config.get('nexus',{})
            db_config = nexus_config.get('db', {})
            if db_config.get('startup_sync'):
                self.sync()
            if db_config.get('startup_vacuum'):
                self.vacuum()

            # Clean up the registration database so that the states are correct
            self.vacuum_registrations()

            # Then schedule it
            schedule.every(2).minutes.do(self.cron_vacuum_sessions).tag('component')
            schedule.every(2).minutes.do(self.cron_vacuum_registrations).tag('component')
            schedule.every(1).minutes.do(self.cron_vacuum_otps).tag('component')
            schedule.every(1).seconds.do(self.cron_handle_alerts).tag('component')

            # Start the scheduler loop
            initialize('crossbar')
            log.info(f"Internal cron schedule started")

        except Exception as ex:
            log.error(f"Unable to finalize startup sequence (sync, "
                      f"vacuum, scheduler, and izaber.initialize) : <{ex}>")

