from lib import *

import swampyer
import re

initialize('nexus')

ROSTER_REGISTER = 'system.roster.register'
ROSTER_UNREGISTER = 'system.roster.unregister'
ROSTER_QUERY = 'system.roster.query'

ROSTER_KEY = 'roster.test'

def connect(login, password):
    client = swampyer.WAMPClientTicket(
                url="ws://localhost:8282/ws",
                realm="izaber",
                username=login,
                password=password,
                auto_reconnect=False,
            ).start()
    return client

def test_connect():
    reset_env()
    create_roles()

    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec = create_user(role='backend')
        client = connect(login, password)
        assert client

        # Create a second user to get information about this roster entry
        login2, password2, user_rec2 = create_user()
        client2 = connect(login2, password2)
        assert client2

        # Create a third user to get information about this roster entry
        login3, password3, user_rec3 = create_user(role='public')
        client3 = connect(login3, password3)
        assert client3

        # Create a forth user that should have full access to everything
        login4, password4, user_rec4 = create_user(role='trust')
        client4 = connect(login4, password4)
        assert client4

        ###############################################################
        # Add ourselves to the roster for the `test_roster` key
        ###############################################################
        dummy_data = {
          'test': 'data'
        }
        result = client.call(ROSTER_REGISTER, ROSTER_KEY, dummy_data, visibility=['frontend'])
        assert result

        ###############################################################
        # Can we get the information via the roster key?
        ###############################################################
        result = client2.call(ROSTER_QUERY, ROSTER_KEY)
        assert result
        assert len(result) == 1
        assert result[0]['test'] == 'data'
        assert len(result[0].keys()) == 1

        ###############################################################
        # We don't want public users to have access to the data
        ###############################################################
        result = client3.call(ROSTER_QUERY, ROSTER_KEY)
        assert not result
        assert len(result) == 0

        ###############################################################
        # We want to ensure that trust and trusted have full access
        ###############################################################
        result = client4.call(ROSTER_QUERY, ROSTER_KEY)
        assert result
        assert len(result) == 1
        assert result[0]['test'] == 'data'

        ###############################################################
        # Let's amend the data with some new stuff
        ###############################################################
        dummy_data['test'] = 'mo data'
        result = client.call(ROSTER_REGISTER, ROSTER_KEY, dummy_data, visibility=['frontend'])
        assert result

        ###############################################################
        # We should only see the current data and nothing else
        ###############################################################
        result = client2.call(ROSTER_QUERY, ROSTER_KEY)
        assert result
        assert len(result) == 1
        assert result[0]['test'] == 'mo data'
        assert len(result[0].keys()) == 1

        ###############################################################
        # Reset the data
        ###############################################################
        dummy_data['test'] = 'data'
        result = client.call(ROSTER_REGISTER, ROSTER_KEY, dummy_data, visibility=['frontend'])
        assert result

        ###############################################################
        # We shouldn't be allowed to add a roster entry for anything
        # except something in `roster.*`
        ###############################################################
        with pytest.raises(Exception):
            result = client2.call(ROSTER_REGISTER, 'trigger.fail', dummy_data)

        ###############################################################
        # Let's unregister the roster entry
        ###############################################################
        result = client.call(ROSTER_UNREGISTER, ROSTER_KEY)
        assert result

        # Nothing should be left behind
        result = client2.call(ROSTER_QUERY, ROSTER_KEY)
        assert not result

        # Then let's reregister
        result = client.call(ROSTER_REGISTER, ROSTER_KEY, dummy_data, visibility=['frontend'])
        assert result

        # And we should get results again
        result = client2.call(ROSTER_QUERY, ROSTER_KEY)
        assert result
        assert len(result) == 1
        assert result[0]['test'] == 'data'

        ###############################################################
        # Vacuum FIXME
        ###############################################################

        # Make sure we don't clobber when we do a vacuum
        result = client.call('system.vacuum')
        assert result

        # And we should get results again
        result = client2.call(ROSTER_QUERY, ROSTER_KEY)
        assert result
        assert len(result) == 1
        assert result[0]['test'] == 'data'

        ###############################################################
        # Let's remove the session holding the data
        ###############################################################
        client.disconnect() # Should nuke the roster entry
        time.sleep(1)

        # This should now have no results
        result = client2.call(ROSTER_QUERY, ROSTER_KEY)
        assert len(result) == 0


    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

