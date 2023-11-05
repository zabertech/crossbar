from lib import *

import swampyer

initialize()

def connect(login, password):
    client = swampyer.WAMPClientTicket(
                url="ws://localhost:8282/ws",
                realm="izaber",
                username=login,
                password=password,
                auto_reconnect=False,
            ).start()
    return client

def hello(invoke, name):
    return f"Hello {name}!"

def hello_reauth(invoke, name):
    return f"reauth {name}"

def test_connect():
    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec, user_obj = create_user()

        # Do a valid connection
        client = connect(login, password)
        assert client

        # Create 10 random users
        user_recs = {}
        for i in range(10):

            login, password, user_rec, user_obj = create_user()
            user_rec['session'] = connect(login, password)
            user_recs[login] = user_rec

        ###############################################################
        # Rapidly register and unregister a uri via session kill to find out if we're
        # doing a good job cleaning up
        ###############################################################
        last_login = user_rec['login']
        last_password = user_rec['plaintext_password']
        for i in range(10):
            # New session so we can just drop it
            new_session = connect(last_login, last_password)

            # Register a URI
            reg_res = new_session.register(
                            'com.izaber.wamp.frontend.bananas',
                            hello,
                            details={
                                'invoke': 'last',
                                'force_reregister': True
                            }
                        )
            assert reg_res == swampyer.WAMP_REGISTERED

            new_session.disconnect()

    finally:
        p.terminate()
        p.wait()

initialize()

if __name__ == "__main__":
    test_connect()

