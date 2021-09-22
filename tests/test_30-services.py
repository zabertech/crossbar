from lib import *

import swampyer

initialize('nexus')

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
        client = swampyer.WAMPClientTicket(
                    url="ws://localhost:8282/ws",
                    realm="izaber",
                    username=login,
                    password=password,
                ).start()
        assert client

        # Create 10 random users
        for i in range(10):
            profile = faker.simple_profile()
            user_rec = {
                    'login': profile['username'],
                    'plaintext_password': secrets.token_hex(16),
                    'role': DEFAULT_ROLE,
                    'name': profile['name'],
                    'source': AUTH_SOURCE_LOCAL,
                    'email': profile['mail'],
                    'upn': f"{profile['username']}@nexus",
                }
            user_obj = db.users.create_(user_rec)

        ###############################################################
        ###############################################################

        # TEST URI: com.izaber.wamp.whoami
        who_res = client.call('com.izaber.wamp.auth.whoami')
        assert who_res['authid']  == login
        assert who_res['role']  == DEFAULT_ROLE

        # TEST URI: com.izaber.wamp.domain.authenticate
        auth_res = client.call('com.izaber.wamp.auth.authenticate', login, password)
        assert auth_res
        auth_res = client.call('com.izaber.wamp.auth.authenticate', login, password+'broken')
        assert not auth_res

        # TEST URI: com.izaber.wamp.ad.users
        users_res = client.call('com.izaber.wamp.ad.users')
        assert users_res
        assert len(users_res) == 100

        # TEST URI: com.izaber.wamp.ad.ldap.groups
        groups_res = client.call('com.izaber.wamp.ad.groups')
        assert groups_res
        assert len(groups_res) == 10

    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

