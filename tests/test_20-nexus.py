from lib import *

import re
import txaio
import swampyer

from distutils.dir_util import copy_tree

YAML_PREF_TEST = """
something:
  goes:
    here: right
    there: 1
""".strip()

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

        assert user_obj
        assert user_obj.login == login
        assert user_obj.role == DEFAULT_ROLE
        assert user_obj.password
        assert user_obj.password != password
        assert passlib.hash.pbkdf2_sha256.using().verify(password, user_obj.password)

        # Do an invalid conneciton
        with pytest.raises(swampyer.exceptions.ExAbort):
            client = swampyer.WAMPClientTicket(
                            url="ws://localhost:8282/ws",
                            realm="izaber",
                            username=login,
                            password=password+'broken',
                        ).start()

        # Another invalid connection
        try:
            client = swampyer.WAMPClientTicket(
                            url="ws://localhost:8282/ws",
                            realm="izaber",
                            username=None,
                            password=password,
                        ).start()
        except swampyer.exceptions.ExAbort as ex:
            assert not re.search('Internal Error', ex.args[0])

        # And yet another invalid connection
        try:
            client = swampyer.WAMPClientTicket(
                            url="ws://localhost:8282/ws",
                            realm="izaber",
                            username=login+'-SHOULDNOTEXIST',
                            password=password,
                        ).start()
        except swampyer.exceptions.ExAbort as ex:
            assert not re.search('Internal Error', ex.args[0])


        # Do a valid connection
        client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert client

        # Do a valid connection where we mangle the case of the login
        client_casing = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login.upper(),
                        password=password,
                    ).start()
        assert client_casing
        res = client_casing.call('auth.whoami')

        ###############################################################
        # Unix Socket Connection
        ###############################################################

        # Do a valid connection
        unix_socket_client = swampyer.WAMPClientTicket(
                        url="unix:///tmp/test-nexus.socket",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert unix_socket_client

        ###############################################################
        # Unix Socket Connection
        ###############################################################

        # Do a valid connection
        raw_socket_client = swampyer.WAMPClientTicket(
                url="tcpip://127.0.0.1:18081",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert raw_socket_client

        ###############################################################
        # Authorization validations
        ###############################################################
        HELLO_URI = 'com.izaber.wamp.frontend.what'
        WHOAMI_URI = 'com.izaber.wamp.auth.whoami'

        # Should be prevented
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            client.register('com.izaber.wamp.private', hello)

        # Now register something on something we should be able to
        # register on
        reg_res = client.register(HELLO_URI, hello)
        assert reg_res == swampyer.WAMP_REGISTERED

        # Can we call the uri?
        call_res = client.call(HELLO_URI, 'bananas')
        assert call_res == 'Hello bananas!'

        # Since it's so soon after login, we'll have extended auth enabled
        # so we're going to expire it for now
        client.call('com.izaber.wamp.auth.reauthenticate_expire')

        # This should return false since we're no longer auth'd
        status_res = client.call('com.izaber.wamp.auth.is_reauthenticated')
        assert not status_res

        # Then this call should fail
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            try:
                reg_res = client.register('com.izaber.wamp.reauth.required', hello_reauth)
            except Exception as ex:
                print("GOT EXCEPTION:", ex, type(ex))
                raise
            print("GOT:", reg_res)

        # Then let's reauthenticate
        reauth_res = client.call('com.izaber.wamp.auth.reauthenticate', password)
        assert reauth_res

        # This should return an integer since we're again authenticated
        status_res = client.call('com.izaber.wamp.auth.is_reauthenticated')
        assert status_res > 0

        # Let's extend the duration of the authenticated session
        ref_res = client.call('com.izaber.wamp.auth.refresh_authorizer')

        # Then let's reattempt regististration
        reg_res = client.register('com.izaber.wamp.reauth.required', hello_reauth)
        assert reg_res == swampyer.WAMP_REGISTERED

        # Can we call it?
        call_res = client.call('com.izaber.wamp.reauth.required', 'potato')
        assert call_res == 'reauth potato'

        ###############################################################
        # OTP - One Time Passwords
        ###############################################################

        # Let's use the DB to create some OTP entries for the user
        otp = []
        for i in range(10):
            otp_obj = user_obj.otps.create_({})
            otp.append(otp_obj)

        # Can we log in with each of them?
        for otp_obj in otp:
            auth_res = client.call('com.izaber.wamp.auth.authenticate',
                                    login,
                                    otp_obj.plaintext_key)
            assert auth_res

        # We should not be able to login with them again
        for otp_obj in otp:
            auth_res = client.call('com.izaber.wamp.auth.authenticate',
                                    login,
                                    otp_obj.plaintext_key)
            assert not auth_res

        # Great, let's add a restriction on an OTP
        otp_obj = user_obj.otps.create_({
                      'permissions': [{
                          'uri': WHOAMI_URI,
                          'perms': 'c'
                      }],
                  })

        # Connect with the limited access key
        client2 = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=otp_obj.plaintext_key,
                    ).start()
        assert client2

        who_res = client2.call(WHOAMI_URI)
        assert who_res['authid']  == login
        assert who_res['role']  == DEFAULT_ROLE

        # Should be prevented
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            hello_res = client2.call(HELLO_URI)

        # Can we create an API key for ourselves?
        new_otp = client.call('com.izaber.wamp.my.otp.create')
        assert new_otp
        plaintext_key = new_otp['plaintext_key']
        assert plaintext_key
        assert new_otp['login'] == login

        # Connect with the generated key
        client3 = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=plaintext_key,
                    ).start()
        assert client3

        # Create a super user
        trusted_login, trusted_password, trusted_user_rec, trusted_user_obj = create_user('trust')

        # The average user should not be able to create a OTP for anyone else
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            result = client3.call('com.izaber.wamp.system.otp.create', trusted_login)

        # However, the super user should be able to create a OTP for anyone else
        trusted_client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=trusted_login,
                        password=trusted_password,
                    ).start()
        assert trusted_client
        new_otp = trusted_client.call('com.izaber.wamp.system.otp.create', login)
        assert new_otp

        # Can we login with the generated key. We also verify the identity
        client3 = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=new_otp['plaintext_key'],
                    ).start()
        assert client3

        who_res = client3.call(WHOAMI_URI)
        assert who_res['authid']  == login
        assert who_res['role']  == DEFAULT_ROLE

        ###############################################################
        # API Keys
        ###############################################################

        # Let's use the DB to create some keys for the user
        apikeys = []
        for i in range(10):
            apikey_obj = user_obj.apikeys.create_({
                                'description': common.sentence(),
                            })
            apikeys.append(apikey_obj)

        # Can we log in with each of them?
        for apikey_obj in apikeys:
            auth_res = client.call('com.izaber.wamp.auth.authenticate',
                                    login,
                                    apikey_obj.plaintext_key)
            assert auth_res

        # Great, let's add a restriction on the first key
        apikey_obj = apikeys[0]
        apikey_obj.permissions = [{
                    'uri': WHOAMI_URI,
                    'perms': 'c'
                }]
        apikey_obj.save_()

        # Connect with the limited access key
        client2 = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=apikey_obj.plaintext_key,
                    ).start()
        assert client2

        who_res = client2.call(WHOAMI_URI)
        assert who_res['authid']  == login
        assert who_res['role']  == DEFAULT_ROLE

        # Should be prevented
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            hello_res = client2.call(HELLO_URI)

        # What does wamp tell us our keys are? There should be 10
        apikeys = client.call('com.izaber.wamp.system.db.query', 'apikeys', [])
        assert apikeys['hits'] == 10

        # Now we can test the wamp based key creation
        key_desc = common.sentence()

        localtz = pytz.timezone('America/Vancouver')
        now = datetime.datetime.now(localtz)
        future = now + datetime.timedelta(seconds=0.5)
        future_str = str(future)

        apikey_rec = client.call('com.izaber.wamp.my.apikeys.create', {
                                            'description': key_desc,
                                            'expires': future_str,
                                            'permissions': [{
                                                    'uri': WHOAMI_URI,
                                                    'perms': 'c'
                                                }]
                                        })
        
        assert apikey_rec
        assert apikey_rec['description'] == key_desc
        assert apikey_rec['expires'] == future_str
        assert len(apikey_rec['permissions']) == 1

        # Let's login with the new key
        client3 = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=apikey_rec['plaintext_key'],
                    ).start()
        assert client3

        # We should be allowed to call whoami 
        who_res = client3.call(WHOAMI_URI)
        assert who_res['authid']  == login
        assert who_res['role']  == DEFAULT_ROLE

        # But not allowed to call hello
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            client3.call(HELLO_URI)

        time.sleep(1)

        # This should fail since the expiry will have passed
        with pytest.raises(swampyer.exceptions.ExAbort):
            client4 = swampyer.WAMPClientTicket(
                            url="ws://localhost:8282/ws",
                            realm="izaber",
                            username=login,
                            password=apikey_rec['key'],
                        ).start()

        # And since the key is expired, we shouldn't be allowed to
        # make more calls on the successfully logged in key either
        with pytest.raises(swampyer.exceptions.ExInvocationError):
            client3.call(WHOAMI_URI)

        ###############################################################
        # Connect as Anonymous User
        ###############################################################

        # Do a valid connection
        anon_client = swampyer.WAMPClient(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                    ).start()
        assert anon_client

        # This should work
        reg_res = anon_client.register('public.allowed', hello)
        assert reg_res == swampyer.WAMP_REGISTERED

        ###############################################################
        # Change role of user
        ###############################################################

        user_obj.role = 'trust'
        user_obj.save_()

        # Do a valid connection
        client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert client

        who_res = client.call(WHOAMI_URI)
        assert who_res['authid']  == login
        assert who_res['role']  == 'trust'

        ###############################################################
        # Database change detection tests
        ###############################################################

        # Let's add a new user via copying
        test_user = user_obj
        ownership_path = test_user.ownership_path_resolve_(
                                test_user._key_value,
                                test_user.parent_
                            )

        new_login = 'bananas'
        source_path = ownership_path.resolve()
        target_path = source_path.parent / new_login

        import shutil
        shutil.copytree(source_path, target_path)

        # Do a valid connection
        test_client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=new_login,
                        password=password,
                    ).start()
        assert test_client

        who_res = test_client.call(WHOAMI_URI)
        assert who_res['authid']  == new_login
        assert who_res['role']  == 'trust'

        # Okay, let's change the role to frontend, what happens on the next login?
        test_user = db.users[new_login]
        test_user.role = 'frontend'
        test_user.save_()

        # Do a valid connection
        test_client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=new_login,
                        password=password,
                    ).start()
        assert test_client

        who_res = test_client.call(WHOAMI_URI)
        assert who_res['authid']  == new_login
        assert who_res['role']  == 'frontend'

        ###############################################################
        # Preferences
        ###############################################################

        meta_key = 'some.key'
        meta_value = 'some value'
        meta_value_changed = 'some value changed'

        meta_res = client.call('com.izaber.wamp.my.metadata.set', meta_key, meta_value)
        assert meta_res == meta_value

        recall_res = client.call('com.izaber.wamp.my.metadata.get', meta_key)
        assert recall_res == meta_value

        meta_res = client.call('com.izaber.wamp.my.metadata.set', meta_key, meta_value_changed)
        assert meta_res == meta_value_changed

        recall_res = client.call('com.izaber.wamp.my.metadata.get', meta_key)
        assert recall_res == meta_value_changed

        update_res = client.call('com.izaber.wamp.my.metadata.set', 
                                meta_key,
                                YAML_PREF_TEST,
                                yaml=True
                            )
        assert update_res

        recall_res = client.call('com.izaber.wamp.my.metadata.get', meta_key)
        assert recall_res
        assert 'something' in recall_res

        list_res = client.call('com.izaber.wamp.my.metadata.get', meta_key)
        assert list_res

        recall_res = client.call('com.izaber.wamp.my.metadata.get', meta_key, yaml=True)
        assert recall_res.strip() == YAML_PREF_TEST

        recall_res = client.call('com.izaber.wamp.system.db.query',
                                            'users',
                                            [ ['login','=',login] ],
                                            yaml=True)
        assert recall_res
        assert recall_res['hits'] == 1
        recall_user_rec = recall_res['records'][0]
        assert recall_user_rec
        assert recall_user_rec['metadata']
        assert recall_user_rec['metadata'][0]['value'].strip() == YAML_PREF_TEST

        client.call('com.izaber.wamp.my.metadata.delete', meta_key)

        recall_res = client.call('com.izaber.wamp.my.metadata.get', meta_key)
        assert not recall_res

    finally:
        p.terminate()
        p.wait()

initialize()

if __name__ == "__main__":
    test_connect()

