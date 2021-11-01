# Nexus Sessions

## Description

For sessioning which ties into authorization, we need to know the following for the server as well as for other systems providing services (eg. Zerp)

- Information about who is logged in `authid` and their `authrole`
- How the login was done
  - If logon was via API key, there might be additional restrictions placed upon the key
- If the session has been recently authenticated. A recent successful authentication will be needed to allow elevated access

Sessions are also intimately tied in with cookies as cookies may outlive session but will still be required to retain information related to that "login". For instance, the elevated authentication status must be "sticky" even if the user performs a refresh on their browers (which would normally destroy the existing session and create a new session upon reconnect)

So details

### Crossbar Sessions

- **Purpose:** As users can login via authid/authtoken or even use anonymous connections, state must be tracked. These sessions are the basic unit that tracks a single connection's state from the connection to the websocket port to the disconnection
- **Scope:** Only while the websocket/rawsocket connection is alive. The session ID is provided to the dynamic `authenticator` and `authorizer`. A connection session is guaranteed while a cookies are not since cookies are not required for connecting and rawsockets do not use cookies anyways. Each tab in a browser will receive a new session.
- **Notes:** Sessions from a metadata perspective (non-registration/subscription data), generally only need `realm`, `authid`, `authrole`, and `authextra`. The `authextra` data is the only field that crossbar components may set. However, **information in `authextra` must not be private/sensitive** as any call with `disclose_me` will pass the contents of `authextra` to the registered function in the `details` argument. Once set, `authextra` may not be changed.

### Authentication Cookies

- **Purpose:** Allows a websocket connection to bypass authid/authtoken based authentication when someone refreshes their browser
- **Scope:** Exists until the cookie times out. Also can be considered dead if the brower or the cookie value itself is lost (ie. via hard refresh with cookie store removal). Cookies will likely outlive sessions due to the use of refresh (kills the websocket connection dropping the existing session, and the reconnection will create a new session) as well as restarting the application. Multiple tabs in a browser will reuse the same cookie to authenticate at which point, each tab will receive a new Crossbar Session.
- **Notes:** Data in the Cookie store must have all the information required to allow the reconstruction of a Crossbar Session when someone reconnects. So the fields: `realm`, `authid`, `authrole`, and `authextra`. Other things such as registrations and subscriptions will need rebuilding by the client after reconnection.

### Nexus Session Cache

- **Purpose:** To hold state information such as if the user has recently connected for elevated authentication, any restrictions that this session may have (if they connect via API key that has a limited scope), etc. This information is used by the dynamic authenticator to validate actions on any URIs
- **Scope:** This is for metadata that should stick to a session but also survive refreshes of the browser. It's not possible to attach this type of data to Crossbar Sessions as that data will disappear with a refresh. It's also not possible to focus on Authentication Cookies as not all connections to Nexus will use cookies. If cookies are used, metadata set in the Nexus Session will be available across all browser tabs logged in with the same cookie.
- **Notes:** For this to be possible we take advantage of the `authextra` field to hold a special token that links to a NexusCookie. This information will live for as long as the cookie does and doesn't require any special messing around with the underlying system. The challenge is when it comes to expiring old data. Access to existing cookies is not readily available so this is where we end up needing to do some hacking to hook into the system underneath to tie the expiration of cookies to the expiration of Nexus Sessions. More on this later

## Nexus Session Process

### 1. Session Creation

When a user first connects to authenticate, the dynamic authenticator at `com.izaber.wamp.auth.authenticator` is invoked with the details on the call including: `login`, `password`, `transport` information. We use this information to validate against a locally hashed password or attempt to bind using the credentials to the configured ldap server. The transport will also provide the crossbar tracking id via `transport['cbtid']`. In the case of `RawSocket` connections, this value will be null.

Upon successful authentication, can create a new `NexusCookie` with a cryptographically secure token that gets preserved across sessions. The `NexusCookie` currently stores two pieces of information:

 - the list of restrictions associated with the original authentication method
 - the status of elevated authentication
 
 Due to the flexiblity, it probably is worth looking into storing other metadata in the future. The new `NexusCookie` token is stored in the `authextra['cache_id']`. This information becomes relevant in the authorization section. 

### 2. URI Authorization

When the client requests to perform a URI action, the dynamic authorizer at `com.iaber.wamp.auth.authorizer` is called. This function receives the `session` argument giving us access to the `session['authextra']['cache_id']`.

The `cache_id` is used to find the `NexusCookie` associated which which contains information such as additional restrictions associated with this session and/or elevated privilege status.

### 3. Session Maintenance

Crossbar Sessions are maintained until the websocket disconnects.

Authentication Cookies are a weird beast; By default Crossbar appears to hold on to cookie sessions indefinitely. This may be a bug so a [ticket has been submitted](https://github.com/crossbario/crossbar/issues/1877) to find out.

Some modifications are made our local `cookiestore.py` so that if nothing related to a cookie is used for the `max_age` duration, the metadata associated with the Authentication Cookie is flushed along with the Nexus Session. Said explicitly, the Authentication Cookie is considered stale after the last associated session disconnects + `max_age` seconds.

There are two methods of keeping track to see if a session is stale yet.

1. When a session disconnects, the system will update the `mtime` of a NexusCookie
2. Every X minutes, the system will cascade through and update the `mtimes` for the current timestamp. As the `mtime` would otherwise only get updated when sessions disconnect, an abrupt terminations (ie.`kill -9`) will cause the system to crash out without notifying the database of activity.

### 4. Session Reaping

Crossbar Sessions are reaped when the socket disconnects.

Authentication Cookies, are removed by Nexus in two situations:

1. Upon a connection, if any code attempts to use `CookieStore.`.

## Crossbar Challenges

While crossbar does allow metadata caching within a session, it's very limited. We are unable to modify it once set and the metadata becomes available to all recipients of messages that receive `details` via the `disclose_me` flag.

Accessing the underlying cookie architecture is almost impossible. Crossbar **does not** make it easy to hook into the cookie system so we end up aggressively monkeypatching the entire thing with the following docker code:

```Dockerfile
RUN ...
    && mv /opt/pypy/site-packages/crossbar/router/cookiestore.py \
          /opt/pypy/site-packages/crossbar/router/oldcookiestore.py \
    && ln -s /app/nexus/lib/hacks/cookiestore.py \
                /opt/pypy/site-packages/crossbar/router/cookiestore.py \
```

-----------------------------------------
# Might be no longer required
-----------------------------------------

## Nexus Session Process

### Session Creation

When a user first connects to authenticate, the dynamic authenticator at `com.izaber.wamp.auth.authenticator` will be invoked.

Upon successful authentication, we create a new `NexusCookie` with a uuid that will then get stored in the `authextra` field.





When a user first connects the dynamic authenticator will receive in the `details` argument

If it's a websocket based connection:

```python
{'authextra': None,
 'authmethod': 'ticket',
 'session': 4987526421649324,
 'ticket': '62963fe6103c8a7f9fb81e141a8150a8',
 'transport': {'cbtid': 'ldiEk0lnP3O6iO5p-9yVve77hJOVSGZV',
               'channel_id': '0000000000000000000000000000000000000000000000000000000000000000',
               'http_headers_received': {'connection': 'Upgrade',
                                         'host': 'localhost:8282',
                                         'origin': 'http://localhost:8282',
                                         'sec-websocket-key': 'MZna7oPcZVnmnMYXrBgzRg==',
                                         'sec-websocket-protocol': 'wamp.2.json,wamp.2.cbor,wamp.2.msgpack',
                                         'sec-websocket-version': '13',
                                         'upgrade': 'websocket'},
               'http_headers_sent': {'Set-Cookie': 'cbtid=ldiEk0lnP3O6iO5p-9yVve77hJOVSGZV;max-age=60'},
               'peer': 'tcp4:127.0.0.1:38838',
               'protocol': 'wamp.2.json',
               'type': 'websocket',
               'websocket_extensions_in_use': []}}

```

Or a rawsocket connection:

```python
{'authextra': None,
 'authmethod': 'ticket',
 'session': 2396410959974679,
 'ticket': '1d9dd2e88761013abec6a4e90025bafe',
 'transport': {'channel_id': '0000000000000000000000000000000000000000000000000000000000000000',
               'peer': 'unix:None',
               'protocol': 'wamp.2.json',
               'type': 'rawsocket'}}
```

Upon successful auth validation (local auth or via LDAP) the system will create a new `NexusCookie` entry. The key to this information should be stored in the `authextra` field.

Oddly enough, there's no way to determining if future connections will be using a cookie or not. Regardless of the situation, it seems like the `cbtid` will be set.



As the system has overridden `RouterSession` via `hack.session.RouterSession`, Nexus will create a second session cache keyed by the `session_id` value upon the creation of a new session. This piggybacks the session initiation code so that we have a Nexus-only session cache rather than trying to store additional data in the Crossbar cache. This is done to limit the potential side-effects and potential affects from code-changes in the future.

`RouterSession._pending_session_id` gets set via the `onMessage` call. The actual `RouterSession._session_id` gets finalized when `def welcome` gets called with `onJoin`.

So the internal session cache is created when the dynamic authenticator located at `com.izaber.wamp.auth.authenticator` successfully logs the user in. The code is found within `component.auth.AuthenticatorSession`.

## Basics

### Bare bones

If no cookies are being used, the system only needs to keep track of the connection's session information. Primarily what we're interested in are the following:

- `authrole`: which the underlying authorization system relies upon
- `authid`: which allows registerations/subscriptions identify who is making requests/publications
- We are also interested in the means of authentication

The final point is important and also the cause of a fair bit of grief on our end. We use dynamic authentication and it generally uses 





Python scripts and other low level automation will probably just rely on simple sessions.


### Web browsers

Using something like autobahn and especially over the web, say for dashboard, the ability to reconnect with a particular account becomes important. Otherwise a simple `F5` will force a user to reauthenticate... which would get immensely annoying.

If allowed, crossbar will then create a cookie which will stand as an authentication token for reestablishing connection after a websocket gets disconnected.

The minimal information required for this is something that allows the system to rebuild the requisite parts of the session information.





