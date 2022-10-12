from lib import *

import time
import re
import swampyer
import swampyer.messages
from http.cookies import SimpleCookie

class OOBHandler(swampyer.WAMPClientTicket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.welcome_data = []

    def handle_welcome(self, welcome):
        super().handle_welcome(welcome)
        self.welcome_data.append(welcome)

def test_connect():
    reset_env()
    create_roles()

    # And launch the nexus server
    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec, user_obj = create_user('trusted')

        client = OOBHandler(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert client

        # We are going to forge another Authenticate request to the server
        # which would normally trigger an error
        client.welcome_data.clear()

        client.send_message(
            swampyer.messages.AUTHENTICATE(
                signature = password,
                extra = {},
            )
        )

        time.sleep(1)

        # Pull the welcome message that got sent back to the client
        # out and let's see if it makes sense
        assert client.welcome_data
        welcome = client.welcome_data.pop()

        assert welcome == swampyer.messages.WELCOME
        assert welcome.session_id == client.session_id

    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()


