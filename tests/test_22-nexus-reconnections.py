from lib import *

import swampyer

initialize('nexus')

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
        profile = faker.simple_profile()
        password = secrets.token_hex(16)
        login = profile['username']
        user_rec = {
                'login': login,
                'plaintext_password': password,
                'role': DEFAULT_ROLE,
                'name': profile['name'],
                'source': AUTH_SOURCE_LOCAL,
                'email': profile['mail'],
                'upn': f"{login}@nexus",
            }

        user_obj = db.users.create_(user_rec)

        # Do a valid connection
        client = connect(login, password)
        assert client

        # Create 10 random users
        user_recs = {}
        for i in range(10):
            profile = faker.simple_profile()
            new_login = profile['username']
            new_password = secrets.token_hex(16)
            user_rec = {
                    'login': new_login,
                    'plaintext_password': new_password,
                    'role': DEFAULT_ROLE,
                    'name': profile['name'],
                    'source': AUTH_SOURCE_LOCAL,
                    'email': profile['mail'],
                    'upn': f"{new_login}@nexus",
                }
            user_obj = db.users.create_(user_rec)

            user_recs[new_login] = new_password

            user_rec['session'] = connect(new_login, new_password)
            user_recs[new_login] = user_rec

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

initialize('nexus')

if __name__ == "__main__":
    test_connect()

