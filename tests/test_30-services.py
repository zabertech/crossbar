from lib import *

import swampyer

initialize()

def hello(invoke, name):
    return f"Hello {name}!"

def hello_reauth(invoke, name):
    return f"reauth {name}"

def test_connect():
    reset_env()
    create_roles()
    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec, user_obj = create_user()

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
            create_user()

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
        assert len(users_res) == 100, f"Got {len(users_res)} users rather than 100"

        # TEST URI: com.izaber.wamp.ad.ldap.groups
        groups_res = client.call('com.izaber.wamp.ad.groups')
        assert groups_res
        assert len(groups_res) == 10, f"Got {len(groups_res)} groups rather than 10"

    finally:
        p.terminate()
        p.wait()

initialize()

if __name__ == "__main__":
    test_connect()

