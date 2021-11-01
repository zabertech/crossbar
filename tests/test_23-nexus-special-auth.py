from lib import *

import swampyer
import re

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

def test_connect():
    reset_env()
    create_roles()

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

        ###############################################################
        # Try to register an entry that requires documentation
        ###############################################################
        reg_uri = 'com.izaber.wamp.docsrequired.test'
        try:
            reg_res = client.register(
                            reg_uri,
                            hello,
                            details={
                                    "match": u"prefix",
                                }
                            )

        except swampyer.exceptions.ExInvocationError as ex:
            assert re.search('com.izaber.wamp.error.requiredocumentation', str(ex))

        ###############################################################
        # Let's then add the documentation
        ###############################################################
        doc_reg_res = client.call(
                                'system.document.set',
                                'register',
                                reg_uri,
                                data={
                                    "match": u"prefix",
                                    "description": "Something here",
                                    "contact": "test user"
                                }
                            )

        assert doc_reg_res

        # And because we added the documentation, we should be able to register
        reg_res = client.register(
                        reg_uri,
                        hello,
                        details={
                                "match": u"prefix",
                            }
                        )
        assert reg_res


    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

