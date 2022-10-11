from lib import *

import time
import re
import swampyer
from http.cookies import SimpleCookie

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
            EVENTS.append((warning_type, duration, details))

        client.subscribe('system.event.warning.registration', handler_warnings)

        # We want to create a dummy URI entry that should trigger in a few seconds
        disconnect_time = int(time.time() -60*60*24*7)
        match = 'exact'
        uri = 'reaping.test'
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

                                        'description': 'Test URI to determine if reaping works',
                                        'contact': 'test@example.com',
                                        'disconnect': disconnect_time,
                                        'zombie_lifespan': True,
                                    })

        EVENTS.clear()
        assert not EVENTS

        time.sleep(1)

        # Force a run of the registration vacuum
        assert client.call('system.vacuum.registrations')

        # Set a really short 10 second zombie lifespan
        res = client.call(
                    'system.db.update',
                    [ uri_rec.uuid ],
                    {
                        'zombie_lifespan': 10,
                    }
                )

        EVENTS.clear()
        assert not EVENTS

        # Then force a run
        time.sleep(1)
        assert client.call('system.vacuum.registrations')

        time.sleep(5)

        assert EVENTS
        assert len(EVENTS) >= 1

        warning_type, duration, event = EVENTS.pop(0)

        assert event['uri'] == uri
        assert warning_type == 'zombie_reap'

    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

