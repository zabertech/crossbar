from lib import *

import swampyer
import re

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

def test_connect():
    reset_env()
    create_roles()

    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec, user_obj = create_user()

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

initialize()

if __name__ == "__main__":
    test_connect()

