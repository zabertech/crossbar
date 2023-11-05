"""

We are verifying that the OTP are not going to be able to create new API
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
        login, password, user_rec, user_obj = create_user()

        # Do a valid connection
        client = swampyer.WAMPClientTicket(
                    url="ws://localhost:8282/ws",
                    realm="izaber",
                    username=login,
                    password=password,
                ).start()
        assert client

        # Let's create a default API Key
        otp_rec = client.call(URI_OTP_CREATE)
        assert otp_rec

        # Let's login with the new key
        otp_client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=otp_rec['plaintext_key'],
                    ).start()
        assert otp_client

        # With this client, we should be denied when trying to make api keys
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            otp_rec = otp_client.call(URI_APIKEY_CREATE)

        # We also should be denied access to changing the user password
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            result = otp_client.call('com.izaber.wamp.system.db.update', '', '')

        # We also should be denied access to making OTP records as well
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            result2 = otp_client.call(URI_OTP_CREATE)

        # As there is no way to create OTPs in a way that additional API keys
        # and OTPs become possible, we stop tests here
        # Let's create an api key that explicitly allows other api keys
        # and otps to be made
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            priv_otp_rec = client.call(URI_OTP_CREATE,
                                      { 'permissions': [
                                          { 'uri': URI_APIKEY_CREATE,
                                            'perms': 'c' },
                                          { 'uri': URI_OTP_CREATE,
                                            'perms': 'c' },
                                      ] }
                                  )

    finally:
        p.terminate()
        p.wait()

initialize()

if __name__ == "__main__":
    test_connect()

