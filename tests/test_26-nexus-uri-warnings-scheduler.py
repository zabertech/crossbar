from lib import *

import time
import re
import swampyer
from http.cookies import SimpleCookie

import textwrap

def test_connect():
    reset_env()
    create_roles()

    # And launch the nexus server
    p = launch_nexus()

    try:
        # Create 2 random users
        login, password, user_rec, user_obj = create_user('trusted')

        client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert client

        # We want to listen for disconnection events
        EVENTS = []
        def handler_warnings(event, warning_type, duration, details):
            print(f"WARNING: {warning_type.upper()} {details['key']}")
            EVENTS.append((warning_type, duration, details))

        def dump_events():
            print(f"---- {len(EVENTS)} events queued ----")
            for warning_type, duration, event in EVENTS:
                print(f"{warning_type}: {event['key']}")

        def find_event(needle_warning):
            for event in EVENTS:
                if needle_warning != event[0]: continue
                return event
            dump_events()
            raise Exception(f"Need {needle_warning} not found!")

        client.subscribe('system.event.warning.registration', handler_warnings)

        schedule = textwrap.dedent('''
        * * * * * disconnect_warn_after:10
        0 1 * * * FIXME_WHAT_IS_THIS_ENTRY_FOR:12
        '''.strip())

        # We want to create a dummy URI entry that should trigger in a few seconds
        match = 'exact'
        uri = 'does.not.get.registered'
        uri_rec = db.uris.upsert_( 'register',
                                    match,
                                    uri,
                                    {
                                        'match': 'exact',
                                        'invoke': 'single',
                                        'active': False,
                                        'create': '2000-10-03T01:46:17.479Z',
                                        'system': False,
                                        'peer': '127.0.0.1',
                                        'authid': 'testuser',

                                        'description': 'Test URI for disconnection alerts',
                                        'contact': 'test@example.com',
                                        'disconnect_warn_after': "1",
                                        'disconnect_warn_reminder_after': 2,
                                        'disconnect_warn_last': None,
                                        'disconnect_count_warn_after': 5,
                                        'disconnect_count_warn_reminder_after': 2,
                                        'schedule': schedule,
                                    })

        EVENTS.clear()
        assert not EVENTS

        z = datetime.datetime(2022,  3,  6,  1,  0,  0).timestamp()
        settings = uri_rec.get_schedule_overrides_(z)

        assert settings['disconnect_warn_after'] == 10

        time.sleep(1)

        # Force a run of the registration vacuum
        assert client.call('system.vacuum.registrations')

        # Wait for alerts scanner to finish
        time.sleep(5)
        assert not EVENTS

        time.sleep(7)

        assert EVENTS
        assert len(EVENTS) >= 1
        warning_type, duration, event = EVENTS.pop(0)

        # First notification
        assert event['uri'] == uri
        assert warning_type == 'disconnect'

    finally:
        p.terminate()
        p.wait()

initialize()

if __name__ == "__main__":
    test_connect()

