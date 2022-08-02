#!/usr/bin/python

from lib import *

YAML_PREF_TEST = """
# this is a test
something:
  goes:
    here: right
    there: 1
""".strip()

def test_db():
    reset_env()
    create_roles()

    # We want to remove all role permissions
    # for the default role for now
    role_obj = db.roles[DEFAULT_ROLE]
    assert role_obj

    # Remove all entries for now
    role_obj.permissions.clear()

    # Verify that this role is devoid of uris
    assert not role_obj.permissions

    # Create a few entries
    uri_perms = {
        'com.izaber.wamp.public.*': 'c',
        'com.izaber.wamp.personal.*': 'cr',
        'com.izaber.wamp.elevated.*': 'c+',
        'com.izaber.wamp.chatty.*': 'sp',
        'com.izaber.wamp.docsrequired.*': 'r!c',
    }
    for uri, perms in uri_perms.items():
        role_obj.permissions.append({
                'uri': uri,
                'perms': perms
            })

    # Create a random user
    login, password, user_rec, user_obj = create_user()

    assert user_obj
    assert user_obj.login == login
    assert user_obj.role == DEFAULT_ROLE
    assert user_obj.password
    assert user_obj.password != password
    assert passlib.hash.pbkdf2_sha256.verify(password, user_obj.password)

    # Can we get the user in the datatabase? The call to
    # controller should return a basic dict as it's intended to be used
    # with the component
    user_rec = db.users[login]
    assert user_rec['login'] == login

    # Now, let's login with this user
    auth_res = controller.authenticate(login, password)
    auth_user = auth_res['user']
    assert auth_user.login == login
    assert auth_user.role == DEFAULT_ROLE

    # Great, then let's do an actual login with a cookie
    login_res = controller.login(login, password)
    assert login_res

    cookie_obj = login_res['cookie_obj']
    assert cookie_obj
    assert cookie_obj.data['restrictions'] is None
    assert cookie_obj.data['auth'][0] == AUTH_SOURCE_LOCAL

    extra = login_res['extra']
    assert extra['cache_id'] == cookie_obj.uuid
    assert extra.get('has_restrictions') == False

    # Can we logout? (returns nothing)
    controller.logout(login, cookie_obj.uuid)

    # Key shouldn't exist after logout, however
    with pytest.raises(KeyError):
        result = db.cookies[cookie_obj.uuid]

    # Try and get a nonexisting UUID
    assert not db.get(cookie_obj.uuid)

    ##################################################
    # Enable/Disable Tests
    ##################################################

    # Can we disable the user?
    controller.user_disable(login)

    # Verify that the login attempt will fail
    disabled_auth_res = controller.authenticate(login, password)
    assert disabled_auth_res == None

    disabled_login_res = controller.login(login, password)
    assert disabled_login_res == False

    # Renable and login
    controller.user_enable(login)

    auth_res = controller.authenticate(login, password)
    auth_user = auth_res['user']
    assert auth_user.login == login
    assert auth_user.role == DEFAULT_ROLE

    # Great looks like low level login worked, then let's do an
    # actual login with a cookie
    login_res = controller.login(login, password)
    assert login_res

    cookie_obj = login_res['cookie_obj']
    assert cookie_obj
    assert cookie_obj.data['restrictions'] is None
    assert cookie_obj.data['auth'][0] == AUTH_SOURCE_LOCAL

    ##################################################
    # Authorizations
    ##################################################

    # We should be allowed to 'call' the com.izaber.wamp.public
    # uri
    extra = login_res['extra']
    authz_res = controller.authorize(
                        login,
                        login_res['role'],
                        'com.izaber.wamp.public.allowed',
                        'call',
                        extra
                    )
    assert authz_res == PERM_ALLOW


    # We should not be able to 'publish' to com.izaber.wamp.backend
    # though
    authz_res = controller.authorize(
                        login,
                        login_res['role'],
                        'com.izaber.wamp.backend',
                        'publish',
                        extra
                    )
    assert authz_res == PERM_DENY

    ##################################################
    # Reauthentication
    ##################################################

    # We should be allowed to 'call' the com.izaber.wamp.elevated
    # uri as long as elevated privs have been enabled
    authz_res = controller.authorize(
                        login,
                        login_res['role'],
                        'com.izaber.wamp.elevated.required',
                        'call',
                        extra
                    )
    # We will be allowed since it's so recent after login
    assert authz_res

    # Let's manually trash the setting, however
    cookie_obj.data['last_authentication'] = 0
    cookie_obj.save_()

    authz_res = controller.authorize(
                        login,
                        login_res['role'],
                        'com.izaber.wamp.elevated.required',
                        'call',
                        extra
                    )
    # We should not be allowed
    assert not authz_res

    # That's cool, let's reauthenticate
    controller.reauthenticate(
                        login,
                        password,
                        extra
                    )


    # Trying again after reauthentication
    authz_res = controller.authorize(
                        login,
                        login_res['role'],
                        'com.izaber.wamp.elevated.required',
                        'call',
                        extra
                    )
    # And we should be allowed again
    assert authz_res

    ##################################################
    # Requires Documentation Flags
    ##################################################

    # We should be allowed to 'call' the com.izaber.wamp.elevated
    # uri as long as elevated privs have been enabled
    authz_res = controller.authorize(
                        login,
                        login_res['role'],
                        'com.izaber.wamp.docsrequired.hello',
                        'register',
                        extra
                    )
    # We shouldn't be allowed since there's no documentation associated
    assert authz_res == PERM_REQUIRE_DOCUMENTATION

    # So let's add some documentation

    ##################################################
    # API Keys
    ##################################################

    # Create without expiry
    apikey = user_obj.apikeys.create_({
                    'description': common.sentence(),
                })

    key_login_res = controller.login(login, apikey.plaintext_key)
    cookie_obj = key_login_res['cookie_obj']
    assert key_login_res
    assert cookie_obj
    auth_source, auth_info = cookie_obj.data['auth']
    assert auth_info == apikey.key

    # Create with expiry
    # We're going to make one that is not expired
    # then let it expire
    localtz = pytz.timezone('America/Vancouver')
    now = datetime.datetime.now(localtz)
    future = now + datetime.timedelta(seconds=0.5)

    apikey = user_obj.apikeys.create_({
                    'description': common.sentence(),
                    'expires': str(future),
                })
    key_login_res = controller.login(login, apikey.plaintext_key)
    assert key_login_res

    # Do we have that information?
    user_rec = user_obj.dict_()
    assert user_rec
    assert len(user_rec['apikeys']) == 2
    assert user_rec['apikeys'][0]['plaintext_key']
    assert user_rec['apikeys'][1]['plaintext_key']

    # Then let enough time elapse that it will expire
    time.sleep(1)
    now = localtz.localize(datetime.datetime.now())
    assert now > future
    key_login_res = controller.login(login, apikey.plaintext_key)
    assert key_login_res == False

    # Create a key with specialized permissions
    apikey = user_obj.apikeys.create_({
                    'description': common.sentence(),
                    'permissions': [{
                                'uri': 'com.izaber.wamp.public.allowed',
                                'perms': 'c',
                            }]
                })
    key_login_res = controller.login(login, apikey.plaintext_key)
    assert key_login_res
    extra = key_login_res['extra']
    assert extra['has_restrictions']

    # This call should authorize when using this key
    authz_res = controller.authorize(
                login,
                login_res['role'],
                'com.izaber.wamp.public.allowed',
                'call',
                extra
            )
    assert authz_res == PERM_ALLOW

    # This call should not be (though the role is allowed)
    authz_res = controller.authorize(
                login,
                login_res['role'],
                'com.izaber.wamp.public.notallowed',
                'call',
                extra
            )
    assert authz_res == PERM_DENY

    ##################################################
    # Preferences
    ##################################################

    meta_key = 'some.key'
    meta_value = 'some value'
    meta_value_changed = 'some value changed'

    # Create a metadata
    meta_res = controller.user_metadata_set(login, meta_key, meta_value)
    assert meta_res

    # Get it back
    recalled_meta_value = controller.user_metadata_get(login, meta_key)
    assert recalled_meta_value == meta_value

    # Update it
    controller.user_metadata_set(login, meta_key, meta_value_changed)
    recalled_meta_value = controller.user_metadata_get(login, meta_key)
    assert recalled_meta_value == meta_value_changed

    # Remove it
    controller.user_metadata_remove(login, meta_key)
    with pytest.raises(KeyError):
        recalled_meta_value = controller.user_metadata_get(login, meta_key)

    # Try with yaml input
    meta_res = controller.user_metadata_set(login, meta_key, YAML_PREF_TEST, yaml=True)
    assert meta_res

    # Get the decoded (non-yaml) data
    recalled_meta_value = controller.user_metadata_get(login, meta_key)
    assert recalled_meta_value
    assert 'something' in recalled_meta_value

    # Get the yaml data
    recalled_meta_value = controller.user_metadata_get(login, meta_key, yaml=True)
    assert recalled_meta_value
    assert recalled_meta_value.strip() == YAML_PREF_TEST


    ##################################################
    # Cleanup
    ##################################################

    # Finally we can nuke the user
    db.users[login].delete_()

    # Check that the user is gone
    with pytest.raises(KeyError):
        db.users[login]

initialize('nexus')

if __name__ == "__main__":
    test_db()


