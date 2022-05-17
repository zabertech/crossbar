from lib import *

import re
import swampyer
from http.cookies import SimpleCookie

def test_connect():
    reset_env()
    create_roles()

    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec, user_obj = create_user('trust')

        # Do a valid connection
        client = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert client

        # Let's delete the cookie from the filesystem
        # cbt_id is the cookie value that keys a session
        cookie_store = SimpleCookie()
        cookie_store.load(client.transport.socket.headers['set-cookie'])
        cbtid = cookie_store['cbtid'].value

        # We can use cbt_id to lookup the associated cookie for the user
        cookie_obj = db.cookies.get_(cbtid)
        cookie_obj.yaml_fpath_.unlink()

        # Read up to the current log point
        data = nexus_log_data()

        # Then kill our session
        res = client.disconnect()
        for i in range(50):
            time.sleep(0.2)
            if client.is_connected():
                continue
            break
        else:
            raise Exception("Wasn't able to disconnect!")

        # Capture the newest information
        log_data = nexus_log_data()

        # There should be no KeyError
        assert not re.search('KeyError', log_data), f"KeyError should not be found\n{log_data}"
        assert not re.search('failing', log_data), f"failing information should not be found\n{log_data}"

    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

