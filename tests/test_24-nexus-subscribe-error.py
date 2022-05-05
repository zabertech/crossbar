"""

In one case there was an issue with the authenticator process dying when the subscription
handler failed. This reproduces the issues so that we have something to test against.

----------------------------------------------
Handler Failure for routerworker-worker001-realm-realm001-serviceagent because 'subscription_on_delete() got multiple values for argument 'details''<<class 'TypeError'>>
ARGS: (None, 8168541242236299)
DETAILS: <autobahn.wamp.types.EventDetails object at 0x0000000008a80640>
Fatal error in component: While firing <function wamp_subscription_handler_factory.<locals>.wrap at 0x000000000842e5c0> subscribed under 881555225477300. - subscription_on_delete() got multiple values for argument 'details'
Traceback (most recent call last):
  File "/app/crossbar/router/router.py", line 269, in send
    session._transport.send(msg)
  File "/app/crossbar/router/session.py", line 280, in send
    self._session.onMessage(msg)
  File "/home/zaber/.cache/pypoetry/virtualenvs/nexus-9TtSrW0h-py3.7/site-packages/autobahn/wamp/protocol.py", line 751, in onMessage
    future = txaio.as_future(handler.fn, *invoke_args, **invoke_kwargs)
  File "/home/zaber/.cache/pypoetry/virtualenvs/nexus-9TtSrW0h-py3.7/site-packages/txaio/tx.py", line 366, in as_future
    return maybeDeferred(fun, *args, **kwargs)
--- <exception caught here> ---
  File "/home/zaber/.cache/pypoetry/virtualenvs/nexus-9TtSrW0h-py3.7/site-packages/twisted/internet/defer.py", line 191, in maybeDeferred
    result = f(*args, **kwargs)
  File "/app/nexus/component/base.py", line 51, in wrap
    return handler(*args, **kwargs, details=details)
builtins.TypeError: subscription_on_delete() got multiple values for argument 'details'

"""

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
        login, password, user_rec, user_obj = create_user()

        # Do a valid connection
        client = connect(login, password)
        assert client

        # Now subscribe to a our topic
        def sub_data(*a, **kw):
            pass
        sub_res = client.subscribe(
                    'com.izaber.wamp.frontend.testsub',
                    sub_data
                )
        assert sub_res

        # Unsubscribe in the past would cause the backend component to crash
        unsub_res = client.unsubscribe( sub_res.subscription_id )

        # Then disconnect our client
        client.shutdown()

        # Then this would fail
        client2 = connect(login, password)
        assert client2

    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

