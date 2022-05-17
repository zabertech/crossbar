# use autobahn for now since swampyer doesn't have cookie support
import asyncio
import txaio
txaio.use_asyncio()

from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner

from lib import *

import swampyer

from http.cookies import SimpleCookie

COOKIE_STORE = SimpleCookie()


YAML_PREF_TEST = """
# this is a test
something:
  goes:
    here: right
    there: 1
""".strip()

initialize('nexus')

# This is for logging in
def get_session_cookies( authid, password ):

    cookie_store = SimpleCookie()
    class GetCookieComponent(ApplicationSession):
        """
        An application component using the time service.
        """

        def onConnect(self):
            print(self._transport.http_headers)
            self.join(self.config.realm, ["cookie", "ticket"], authid)

        def onChallenge(self, challenge):
            return password

        async def onJoin(self, details):
            cookie_store.load(self._transport.http_headers['set-cookie'])
            self.leave()

        def onDisconnect(self):
            asyncio.get_event_loop().stop()

        def onLeave(self, details):
            self.disconnect()

        def onDisconnect(self):
            asyncio.get_running_loop().stop()

    runner = ApplicationRunner('ws://localhost:8282/ws', 'izaber')
    runner.run(GetCookieComponent)

    return cookie_store

def session_from_cookie( authid, cookie_store ):

    states = {
                'connect': False,
                'join': False,
                'disconnect': False,
                'leave': False,
            }

    class SetCookieComponent(ApplicationSession):

        def onConnect(self):
            print(f"COOKIE ONCON {authid}")
            states['connect'] = True
            self.join(self.config.realm, ["cookie"], authid)

        async def onJoin(self, details):
            try:
                print(f"COOKIE CONNS {self._transport.http_headers['set-cookie']}")
            except Exception as ex:
                print(f"COOKIE CONNS {self._transport}")
            states['join'] = True
            self.leave()

        def onLeave(self, details):
            states['disconnect'] = details
            print(f"COOKIE LEAVE {authid} {details}")
            self.disconnect()

        def onDisconnect(self):
            states['disconnect'] = True
            print(f"COOKIE DISCO {authid}")
            asyncio.get_running_loop().stop()

    cbtid = cookie_store['cbtid']
    headers = {
                'cookie': cbtid.OutputString(['cbtid']),
            }
    print("SETTING HEADERS TO:", headers)
    runner_cookied = ApplicationRunner('ws://localhost:8282/ws', 'izaber', headers=headers)
    runner_cookied.run(SetCookieComponent)
    
    return states

def test_connect():
    p = launch_nexus()

    try:
        # Create a random user
        login, password, user_rec, user_obj = create_user('trust')

        ########################################################
        # Now we're going to test cookie authentication
        ########################################################

        # Get the cookie
        try:
            cookie_store = get_session_cookies( login, password )
            assert cookie_store
            assert cookie_store['cbtid']
        except Exception as ex:
            raise pytest.fail(f"Login Failed with {ex}")

        # The cookie should still exist in the database
        cbtid = cookie_store['cbtid'].value
        cookie_obj = db.cookies.get_(cbtid)
        assert cookie_obj

        # Make sure we have the session key in the cookie auth extra
        authextra = cookie_obj.authextra
        assert authextra
        cache_id = authextra.get('cache_id')
        assert cache_id

        print("COOKIE TOKEN:", cache_id)

        # Login with the cookie
        states = session_from_cookie( login, cookie_store )
        assert states['join'] == True

        # Sleep for 2 seconds so that we time out the cookie
        import time
        time.sleep(3)

        # And we should be denied access
        states = session_from_cookie( login, cookie_store )
        assert states['join'] == False

        # The cookie should no longer exist in the database as well
        cookie_obj = db.cookies.get_(cbtid)
        assert cookie_obj is None

        ########################################################
        # Now we're going to test cookie authentication
        # when the cookie hasn't been cached yet. This means
        # the cookie once presented, nexus will have to load the
        # data from the disk and build the cache itself
        ########################################################

        # We fake things by creating a new session directly
        login_res = controller.login(login, password)
        assert login_res

        cookie_obj = login_res['cookie_obj']
        assert cookie_obj
        assert cookie_obj.key

        # We attach the new cookie to the 
        cookie_store['cbtid'] = cookie_obj.key

        # And we should be allowed
        states = session_from_cookie( login, cookie_store )
        assert states['join'] == False

        ########################################################
        # Let's now test two things:
        # 1. As long as sessions are active, we keep the record
        #    refreshed
        # 2. When the sessions are inactive beyond a certain point
        #    that the cookies get cleared
        ########################################################

        # Do a connection that we'll keep alive

        client_active = swampyer.WAMPClientTicket(
                        url="ws://localhost:8282/ws",
                        realm="izaber",
                        username=login,
                        password=password,
                    ).start()
        assert client_active
        client_active_cookies = SimpleCookie()
        client_active_cookies.load(client_active.transport.socket.headers['set-cookie'])
        client_active_cbtid = client_active_cookies['cbtid'].value
        assert client_active_cbtid 

        # Do a connection that we'll connect then disconnect
        # so we can ensure that the code will purge the session
        # after it goes stale
        client_inactive_cookies = get_session_cookies(login, password)
        client_inactive_cbtid = client_inactive_cookies['cbtid'].value
        assert client_inactive_cbtid 

        # Now for basically 5 seconds do mutltiple iterations
        # of running vacuum with 1 session disconnect and another
        # remaining connected
        for i in range(5):
            time.sleep(1)
            print("VACUUM:", i)
            client_active.call('com.izaber.wamp.system.vacuum')

        # The dead client's cookie should have been vacuumed by the
        # process
        with pytest.raises(KeyError):
            inactive_cookie_obj = db.cookies[client_inactive_cbtid]

        # The active client's cookie should be available as it was
        # kept alive through the process
        active_cookie_obj = db.cookies[client_active_cbtid]
        assert active_cookie_obj 
        assert not active_cookie_obj.expired_()

    finally:
        p.terminate()
        p.wait()

initialize('nexus')

if __name__ == "__main__":
    test_connect()

