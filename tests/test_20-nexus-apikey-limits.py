"""

We are verifying that the API Keys are not going to be able to create new API
Keys or change their own password by default

"""

from lib import *

import swampyer

initialize()

URI_APIKEY_CREATE = 'com.izaber.wamp.my.apikeys.create'
URI_OTP_CREATE = 'com.izaber.wamp.my.otp.create'

def test_connect():
    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec, user_obj = create_user(role='trust')

        # Do a valid connection
        client = swampyer.WAMPClientTicket(
                    url="ws://localhost:8282/ws",
                    realm="izaber",
                    username=login,
                    password=password,
                ).start()
        assert client

        # Let's create a default API Key
        apikey_rec = client.call(URI_APIKEY_CREATE)
        assert apikey_rec

        # Let's login with the new key
        apikey_client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=apikey_rec['plaintext_key'],
                    ).start()
        assert apikey_client

        # With this client, we should be denied when trying to make api keys
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            apikey_rec = apikey_client.call(URI_APIKEY_CREATE)

        # We also should be denied access to changing the user password
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            result = apikey_client.call('com.izaber.wamp.system.db.update', '', '')

        # We also should be denied access to making OTP records as well
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            result2 = apikey_client.call(URI_OTP_CREATE)

        # Let's create an api key that explicitly allows other api keys
        # and otps to be made
        priv_apikey_rec = client.call(URI_APIKEY_CREATE,
                                  { 'permissions': [
                                      { 'uri': URI_APIKEY_CREATE,
                                        'perms': 'c' },
                                      { 'uri': URI_OTP_CREATE,
                                        'perms': 'c' },
                                  ] }
                              )
        assert priv_apikey_rec

        # Let's login with the new key
        priv_apikey_client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=priv_apikey_rec['plaintext_key'],
                    ).start()
        assert priv_apikey_client

        # With this client, we should be allowed when trying to make api keys
        another_apikey_rec = priv_apikey_client.call(URI_APIKEY_CREATE)
        assert another_apikey_rec 

        # We also should be allowed access to making OTP records as well
        another_otp = priv_apikey_client.call(URI_OTP_CREATE)
        assert another_otp

        # We want to ensure that the new api key is denied creating
        # more api keys
        another_apikey_client =  swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=another_apikey_rec['plaintext_key'],
                    ).start()
        assert another_apikey_client

        # With this client, we should be denied when trying to make api keys
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            apikey_rec = another_apikey_client.call(URI_APIKEY_CREATE )

        # We also should be denied access to changing the user password
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            result = another_apikey_client.call('com.izaber.wamp.system.db.update', '', '')

        # We also should be denied access to making OTP records as well
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            result2 = another_apikey_client.call(URI_OTP_CREATE)

    finally:
        p.terminate()
        p.wait()

initialize()

if __name__ == "__main__":
    test_connect()

