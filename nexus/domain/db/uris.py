import time
import threading
import traceback

from .common import *

from nexus.log import log

##################################################
# NexusURI
##################################################

HISTORY_CONNECT = 0
HISTORY_DISCONNECT = 1
HISTORY_AUTHID = 2
HISTORY_PEER = 3
HISTORY_SESSION_ID = 4

# Hard coded configuration. Maybe we can put this into the izaber.yaml
# Wanted to put the information right into the record but the record also
# started to get way way too verbose

# Maximum size of the disconnection buffer.
HISTORY_SIZE = 100

# How many seconds to look at to determine if we're getting fast disconnects
# Note that the larger the number, slower the response will be.
DISCONNECTION_COUNT_FRAME_SIZE = 600

COLUMNS = NexusSchema.from_yaml("""
version: 1.5

uri:
  help: |-
    What is the URI?
  default:

action:
  help: |-
    The URI is connected to what action? Can be one of
    "register", "publish", "call", "subscribe"
  default:

active:
  help: |-
    Is this URI currently active on the system?
  default: False

system:
  help: |-
    This is a system component?
  default: False

match:
  help: |-
    URI matching policy. can be one of
    "exact", "prefix", "wildcard"
  default: exact

invoke:
  help: |-
    Invocation rule.
  default:

description:
  help: |-
    Description of the purpose of this uri with this action
  default: ''

contact:
  help: |-
    Contact person or owner of the URI
  default:

create:
  help: |-
    When this was last registered
  default:

peer:
  help: |-
    From where was the last connected entry?
  default:

authid:
  help: |-
    The authid of the last connected creator
  default:

session_id:
  help: |-
    The current/last session id for the registration
  default:

disconnect_warn_after:
  help: |-
    Publish to warning disconnection URI after X seconds
  default:
  type: int

disconnect_warn_reminder_after:
  help: |-
    How often to send out reminders?
    If set to null, nexus will not send out reminders after the first notice
  default:
  type: int

disconnect_warn_last:
  help: |-
    Set to when the last disconnection warning was sent
  default:
  type: int

history:
  help: |-
    Connection history for this URI. This should be a list with:
    [
      epoch connection,
      epoch disconnection,
      authid,
      peer,
      sessionid,
    ]
  default: []

disconnect:
  help: |-
    When the URI was disconnected
  default:
  type: int

disconnect_count_warn_after:
  help: |-
    Send a warning if the of disconnect/reconnect beyond this number within
    a minute
  default:
  type: int

disconnect_count_warn_reminder_after:
  help: |-
    How often to send out reminders about fast disconnects?
  default:
  type: int

disconnect_count_warn_last:
  help: |-
    When the last disconnection warning was sent
  default:
  type: int

""")

class NexusURI(NexusRecord):
    # FIXME
    _yaml_template = None
    _schema = COLUMNS
    _key_name = 'key'

    path_format_ = '{parent_path}/{key}/data.yaml'
    ownership_path_format_ = '{parent_path}/{key}/'

    def documented(self):
        # We return True if the owner and description have been defined
        # This is kind of a simplistic solution for now but for now,
        # it doesn't need to be super clever
        return self.contact and self.description

    def mark_registered_(self, force=False):
        """ Called on URI when it should be marked as registered live
        """
        if self.active and not force:
            return

        # Let's submit a log message about a registration coming online
        log.info(f"REG {self.match}://{self.uri} from {self.authid}@{self.peer}")

        # Mark this registration as dead
        self.active = True

        # Let's include the connection information
        now = int(time.time())
        self.history.append([
            now, # epoch connection
            None, # epoch disconnection. None for now
            self.authid,
            self.peer,
            self.session_id,
        ])

        # Is this entry in the list of concerns? let's remove it
        self.parent_._uris_disconnected.pop(self.key, None)

        # Are we looking at this something that requires a disconnection rate
        # warning? If we have gone under the amount, we'll reset for now
        if not self.disconnect_count_exceeded_() and self.disconnect_count_warn_last:
            self.disconnect_warn_last = None

        self.save_()

    def mark_unregistered_(self, force=False):
        """ Called on URI when it should be marked as disconnected
        """

        # Is this already marked disconnected?
        if self.key in self.parent_._uris_disconnected and not force:
            return

        # Note when the registration fell off the bus
        now = int(time.time())

        self.disconnect = now

        # When the last warning was sent (this is a fresh disconnect)
        self.disconnect_warn_last = None

        self.save_()

        # Let's submit a log message about the loss of the registration if we've noticed
        # that we're switching states
        if self.active:
            log.warn(f"REGLOST {self.match}://{self.uri} from {self.authid}@{self.peer}")

        # Mark this registration as dead
        self.active = False

        # Add the current timestamp to the history
        if not self.history:
            self.history.append([
                None,
                None,
                self.authid,
                self.peer,
                self.session_id,
            ])
        self.history[-1][HISTORY_DISCONNECT] = now

        # Reduce disconnect entries if required. list.pop is slow
        # but we don't really expect to need more than a single
        # iteration
        while len(self.history) > HISTORY_SIZE:
            self.history.pop(0)

        # Calculate the disconnection rate over DISCONNECTION_COUNT_FRAME_SIZE
        # seconds
        disconnect_count = self.disconnect_count_alert_required_(now)
        if disconnect_count:

            # Log when we last warned
            if self.disconnect_count_warn_last:
                warning_type = 'disconnect_count_reminder'
            else:
                warning_type = 'disconnect_count'

            self.disconnect_count_warn_last = now

            self.save_()

            # With the alert, we disclose what stage the alert is,
            # whether it's the initial disconnect warning or it's the
            # reminder (if applicable)
            self.parent_._alerts_pending.append((warning_type, disconnect_count, self))
            log.warn(f"{warning_type.upper()} {disconnect_count} {self.key}")

        # Ddd it to the list of things for the system to check for disconnections
        self.parent_._uris_disconnected[self.key] = self

        self.save_()

    def disconnect_count_exceeded_(self, now=None):
        """ Returns true value if the reconnection/disconnection count for this
            URI has exceeded allowed configuration. If the count has exceeded,
            return the rate value which would also be True-truthy
        """
        if not self.disconnect_count_warn_after:
            return

        if not now: now = time.time()

        time_boundary = now - DISCONNECTION_COUNT_FRAME_SIZE
        disconnect_count = 0
        for connection in self.history:
            if connection[HISTORY_DISCONNECT] and \
               connection[HISTORY_DISCONNECT] >= time_boundary:
                disconnect_count += 1

        if disconnect_count < self.disconnect_count_warn_after:
            return

        return disconnect_count

    def disconnect_count_alert_required_(self, now=None):
        """ Returns if need to send a disconnection count notice. We return
            the number of disconnection within the last DISCONNECTION_COUNT_FRAME_SIZE
            if we need to send out an alert
        """

        if not self.disconnect_count_warn_after:
            return

        if not now: now = time.time()

        disconnect_count = self.disconnect_count_exceeded_(now)

        if not self.disconnect_count_warn_last:
            return disconnect_count

        # Are we required to alert?
        if not self.disconnect_count_warn_reminder_after:
            return

        reminder_at = self.disconnect_count_warn_reminder_after + self.disconnect_count_warn_last
        if reminder_at > now:
            return

        return disconnect_count

    def disconnect_warn_after_(self):
        """ Returns the timestamp for which the system should flag a warning
            on this URI should it be disconnected. If no warning is required,
            will just return a false-y value
        """
        if self.active or not self.disconnect_warn_after:
            return

        # Skip any warn entries that are not required to be addressed
        if self.disconnect_warn_last:
            if not self.disconnect_warn_reminder_after:
                return

            return self.disconnect_warn_last + self.disconnect_warn_reminder_after

        # Don't need to send a warning we haven't disconnected
        elif not self.disconnect:
            return

        return self.disconnect + self.disconnect_warn_after

    def disconnect_downtime_alert_required_(self, now=None):
        """ Returns if we need to send a disconnection notice, we return
            the number of seconds that the connection has been down
        """
        if not now: now = time.time()

        warn_after = self.disconnect_warn_after_()

        if not warn_after: return
        if now < warn_after: return

        staleness = int(now - warn_after)

        return staleness

class NexusURIs(_AuthorizedNexusCollection):
    _record_class = NexusURI
    _role_permissions = {
        'trust': True,
        'trusted': True,
        '%default': False,
    }

    _uris_disconnected = {}
    _disconnection_callbacks = {}
    _alerts_pending = []

    def generate_key_(self, action, match, uri):
        """ Returns the encoded key for the URI that considers:

            - action
            - match scheme
            - uri

            Basically this creates a unique key based upon the
            traits we care about uniquely
        """
        return '_'.join([uri, match, action])

    def upsert_(self, action, match, uri, data):
        """ Amends records in the database for URI documentation
        """
        uri_key = self.generate_key_(action, match, uri)

        # Record does exist, let's amend it
        rec = self.get_(uri_key)
        if rec:
            for k, v in data.items():
                setattr(rec, k, v)
            rec.save_()

        # No record exists, let's create it
        else:
            new_rec = {
                'key': uri_key,
                'uri': uri,
                'action': action,
            }
            for k, v in data.items():
                if k not in new_rec:
                    new_rec[k] = v
            rec = self.create_(new_rec)

        return rec

    def upsert_registered_(self, match, uri, data):
        """ When we receive a new registration and we want
            to mark the registration as active, we'd do
            an upsert with a new records.
        """
        reg_rec = self.upsert_('register', match, uri, data)
        reg_rec.mark_registered_(force=True)
        return reg_rec

    def scan_for_disconnect_timeouts_(self):
        """ This should be something that's periodically iterated
            upon to detect dropped registrations of concern. This will simply
            run and add entries to the self._alerts_pending list
        """
        now = time.time()
        for uri_key, uri_rec in self._uris_disconnected.items():
            try:
                # Skip any warn entries that are not required to be addressed
                alert_required = uri_rec.disconnect_downtime_alert_required_()
                if not alert_required: continue

                # Note the type of warning
                if uri_rec.disconnect_warn_last:
                    warning_type = 'disconnect_reminder'
                else:
                    warning_type = 'disconnect'

                # Log when we last warned
                uri_rec.disconnect_warn_last = time.time()

                uri_rec.save_()

                # With the alert, we disclose what stage the alert is,
                # whether it's the initial disconnect warning or it's the
                # reminder (if applicable)
                self._alerts_pending.append((warning_type, alert_required, uri_rec))
                log.warn(f"{warning_type.upper()} {alert_required} {uri_rec.key}")

            except Exception as ex:
                tb = traceback.format_exc()
                log.error(f"Unable to process alert because {ex} {tb}")

    def receive_alerts_(self):
        """ Fetch and flushes the alerts pending
        """
        alerts = self._alerts_pending
        self._alerts_pending = []
        return alerts


