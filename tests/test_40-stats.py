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

        # Register a single URI so we hvae something to look up
        reg_res = client.register('com.izaber.wamp.reauth.required', hello_reauth)
        assert reg_res == swampyer.WAMP_REGISTERED



    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

