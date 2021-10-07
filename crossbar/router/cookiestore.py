#####################################################################################
#
#  Copyright (c) Crossbar.io Technologies GmbH
#  SPDX-License-Identifier: EUPL-1.2
#
#####################################################################################

import os
import json
import datetime

from http import cookies as http_cookies

from autobahn import util

from txaio import make_logger

__all__ = (
    'CookieStoreMemoryBacked',
    'CookieStoreFileBacked',
)


class CookieStore(object):
    """
    Cookie store common base.
    """

    log = make_logger()

    def __init__(self, config):
        """
        Ctor.

        :param config: The cookie configuration.
        :type config: dict
        """
        self._config = config

        # name of the HTTP cookie in use
        self._cookie_id_field = config.get('name', 'cbtid')

        # length of the cookie (random) ID value
        self._cookie_id_field_length = int(config.get('length', 24))

        # lifetime of the cookie in seconds (http://tools.ietf.org/html/rfc6265#page-20)
        self._cookie_max_age = int(config.get('max_age', 86400 * 7))

        # transient cookie database
        self._cookies = {}

        self.log.debug("Cookie stored created with config {config}", config=config)

    def parse(self, headers):
        """
        Parse HTTP header for cookie. If cookie is found, return cookie ID,
        else return None.
        """
        self.log.debug("Parsing cookie from {headers}", headers=headers)

        # see if there already is a cookie set ..
        if 'cookie' in headers:
            try:
                cookie = http_cookies.SimpleCookie()
                cookie.load(str(headers['cookie']))
            except http_cookies.CookieError:
                pass
            else:
                if self._cookie_id_field in cookie:
                    cbtid = cookie[self._cookie_id_field].value
                    if cbtid in self._cookies:
                        return cbtid
        return None

    def create(self):
        """
        Create a new cookie, returning the cookie ID and cookie header value.
        """
        # http://tools.ietf.org/html/rfc6265#page-20
        # 0: delete cookie
        # -1: preserve cookie until browser is closed

        cbtid = util.newid(self._cookie_id_field_length)

        # cookie tracking data
        cbtData = {
            # UTC timestamp when the cookie was created
            'created': util.utcnow(),

            # maximum lifetime of the tracking/authenticating cookie
            'max_age': self._cookie_max_age,

            # when a cookie has been set, and the WAMP session
            # was successfully authenticated thereafter, the latter
            # auth info is store here
            'authid': None,
            'authrole': None,
            'authrealm': None,
            'authmethod': None,
            'authextra': None,

            # set of WAMP transports (WebSocket connections) this
            # cookie is currently used on
            'connections': set()
        }

        self._cookies[cbtid] = cbtData

        self.log.debug("New cookie {cbtid} created", cbtid=cbtid)

        # do NOT add the "secure" cookie attribute! "secure" refers to the
        # scheme of the Web page that triggered the WS, not WS itself!!
        #
        return cbtid, '%s=%s;max-age=%d' % (self._cookie_id_field, cbtid, cbtData['max_age'])

    def exists(self, cbtid):
        """
        Check if cookie with given ID exists.
        """
        cookie_exists = cbtid in self._cookies
        self.log.debug("Cookie {cbtid} exists = {cookie_exists}", cbtid=cbtid, cookie_exists=cookie_exists)
        return cookie_exists

    def getAuth(self, cbtid):
        """
        Return `(authid, authrole, authmethod, authrealm, authextra)` tuple given cookie ID.
        """
        if cbtid in self._cookies:
            c = self._cookies[cbtid]
            cookie_auth_info = c['authid'], c['authrole'], c['authmethod'], c['authrealm'], c['authextra']
        else:
            cookie_auth_info = None, None, None, None, None

        self.log.debug("Cookie auth info for {cbtid} retrieved: {cookie_auth_info}",
                       cbtid=cbtid,
                       cookie_auth_info=cookie_auth_info)

        return cookie_auth_info

    def setAuth(self, cbtid, authid, authrole, authmethod, authextra, authrealm):
        """
        Set `(authid, authrole, authmethod, authextra)` for given cookie ID.
        """
        if cbtid in self._cookies:
            c = self._cookies[cbtid]
            c['authid'] = authid
            c['authrole'] = authrole
            c['authrealm'] = authrealm
            c['authmethod'] = authmethod
            c['authextra'] = authextra

    def addProto(self, cbtid, proto):
        """
        Add given WebSocket connection to the set of connections associated
        with the cookie having the given ID. Return the new count of
        connections associated with the cookie.
        """
        self.log.debug("Adding proto {proto} to cookie {cbtid}", proto=proto, cbtid=cbtid)

        if cbtid in self._cookies:
            self._cookies[cbtid]['connections'].add(proto)
            return len(self._cookies[cbtid]['connections'])
        else:
            return 0

    def dropProto(self, cbtid, proto):
        """
        Remove given WebSocket connection from the set of connections associated
        with the cookie having the given ID. Return the new count of
        connections associated with the cookie.
        """
        self.log.debug("Removing proto {proto} from cookie {cbtid}", proto=proto, cbtid=cbtid)

        # remove this WebSocket connection from the set of connections
        # associated with the same cookie
        if cbtid in self._cookies:
            self._cookies[cbtid]['connections'].discard(proto)
            return len(self._cookies[cbtid]['connections'])
        else:
            return 0

    def getProtos(self, cbtid):
        """
        Get all WebSocket connections currently associated with the cookie.
        """
        if cbtid in self._cookies:
            return self._cookies[cbtid]['connections']
        else:
            return []


class CookieStoreMemoryBacked(CookieStore):
    """
    Memory-backed cookie store.
    """


class CookieStoreFileBacked(CookieStore):
    """
    A persistent, file-backed cookie store.

    This cookie store is backed by a file, which is written to in append-only mode.
    Hence, the file is "growing forever". Whenever information attached to a cookie
    is changed (such as a previously anonymous cookie is authenticated), a new cookie
    record is appended. When the store is booting, the file is sequentially scanned.
    The last record for a given cookie ID is remembered in memory.
    """
    def __init__(self, cookie_file_name, config):
        CookieStore.__init__(self, config)

        self._cookie_file_name = cookie_file_name

        if not os.path.isfile(self._cookie_file_name):
            self.log.debug("File-backed cookie store created")
        else:
            self.log.debug("File-backed cookie store already exists")

        self._cookie_file = open(self._cookie_file_name, 'a')

        # initialize cookie database
        self._init_store()

        if config['store'].get('purge_on_startup', False):
            self._clean_cookie_file()

    def _iter_persisted(self):
        with open(self._cookie_file_name, 'r') as f:
            for c in f.readlines():
                d = json.loads(c)

                # we do not persist the connections
                # here make sure the cookie loaded has a
                # default connections key to avoid key errors
                # other keys that aren't persisted should be set here
                d['connections'] = set()

                yield d

    def _persist(self, id, c, status='created'):

        self._cookie_file.write(
            json.dumps({
                'id': id,
                status: c['created'],
                'max_age': c['max_age'],
                'authid': c['authid'],
                'authrole': c['authrole'],
                'authmethod': c['authmethod'],
                'authrealm': c['authrealm'],
                'authextra': c['authextra'],
            }) + '\n')
        self._cookie_file.flush()
        os.fsync(self._cookie_file.fileno())

    def _init_store(self):
        n = 0
        for cookie in self._iter_persisted():
            id = cookie.pop('id')
            if id not in self._cookies:
                self._cookies[id] = {}
            self._cookies[id].update(cookie)
            n += 1

        self.log.info("Loaded {cnt_cookie_records} cookie records from file. Cookie store has {cnt_cookies} entries.",
                      cnt_cookie_records=n,
                      cnt_cookies=len(self._cookies))

    def create(self):
        cbtid, header = CookieStore.create(self)

        c = self._cookies[cbtid]

        self._persist(cbtid, c)

        self.log.debug("Cookie {cbtid} stored", cbtid=cbtid)

        return cbtid, header

    def setAuth(self, cbtid, authid, authrole, authmethod, authextra, authrealm):

        if self.exists(cbtid):

            cookie = self._cookies[cbtid]

            # only set the changes and write them to the file if any of the values changed
            if authid != cookie['authid'] or authrole != cookie['authrole'] or authmethod != cookie[
                    'authmethod'] or authrealm != cookie['authrealm'] or authextra != cookie['authextra']:
                CookieStore.setAuth(self, cbtid, authid, authrole, authmethod, authextra, authrealm)
                self._persist(cbtid, cookie, status='modified')

    def _clean_cookie_file(self):
        with open(self._cookie_file_name, 'w') as cookie_file:
            for cbtid, cookie in self._cookies.items():
                expiration_delta = datetime.timedelta(seconds=int(cookie['max_age']))
                upper_limit = util.utcstr(datetime.datetime.now() - expiration_delta)
                if cookie['created'] < upper_limit:
                    # This cookie is expired, discard
                    continue

                cookie_record = json.dumps({
                    'id': cbtid,
                    'created': cookie['created'],
                    'max_age': cookie['max_age'],
                    'authid': cookie['authid'],
                    'authrole': cookie['authrole'],
                    'authmethod': cookie['authmethod'],
                    'authrealm': cookie['authrealm'],
                    'authextra': cookie['authextra'],
                }) + '\n'
                cookie_file.write(cookie_record)

            cookie_file.flush()
            os.fsync(cookie_file.fileno())

# Zaber Hacks start here

import time
from izaber import initialize, config
from nexus.domain import controller
from nexus.domain.db import db

# FIXME: need a more elegant way of keeping track of sessions
from nexus.component.domain import SESSIONS

class CookieDB(object):
    def __init__(self):
        self._cookie_store = {}


    def get_cookie_obj(self, id):
        if id not in db.cookies:
            if id in self._cookie_store:
                del self._cookie_store[id]
            return

        # Get the cookie and make sure it has not
        # expired yet
        cookie_obj = db.cookies[id]
        if not cookie_obj.expired_():
            return cookie_obj

        # Okay this cookie has expired. Let's just
        # double check to see if an associated session
        # is still active on the system
        # FIXME: need a more elegant way of keeping track of sessions
        cache_id = cookie_obj.uuid
        for session_id, data in SESSIONS.items():
            extra = data.get('details',{}).get('authextra')
            cache_id_cmp = extra.get('cache_id')
            if not cache_id_cmp:
                continue
            if cache_id == cache_id_cmp:
                cookie_obj.touch_()
                return cookie_obj

        # Newp, it's expired and we need to move on
        del self._cookie_store[id]
        cookie_obj.delete_()

        return

    def __getitem__(self, id):
        cookie_obj = self.get_cookie_obj(id)
        if not cookie_obj:
            raise KeyError(f"No cookie {repr(id)}")

        # If we'll pulling the cookie from the filesystem it
        # won't be in the cache yet so we'll have to prep the
        # local cache with a stub entry
        if id not in self._cookie_store:
            self._cookie_store[id] = cookie_obj.cbt_data()

        return self._cookie_store[id]

    def __setitem__(self, id, val):
        self._cookie_store[id] = val

    def __delitem__(self, id):
        cookie_obj = self.get_cookie_obj(id)
        if cookie_obj:
            cookie_obj.delete_()
        del self._cookie_store[id]

    def __contains__(self, id):
        # We validate against the cookie filesystem database
        if self.get_cookie_obj(id):
            return True
        return False

class CookieStoreMemoryBacked(CookieStore):
    def __init__(self, config):
        super().__init__(config)

        # What we need to do is override the self._cookies object since
        # that will be the part of the code that bridges to the internal
        # file-backed DB
        self._cookies = CookieDB()

    def create(self):
        """
        Create a new cookie, returning the cookie ID and cookie header value.
        """
        # We use token_urlsafe as the official version creates tokens
        # that are not filesystem safe with `/` as one of the possible
        # token characters
        cookie_obj = db.cookies.create_(
                            {
                                #'created': util.utcnow(),
                                'created': time.time(),
                                'max_age': self._cookie_max_age,
                            },
                            key_length=self._cookie_id_field_length
                        )
        cbt_data = cookie_obj.cbt_data()
        cbtid = cookie_obj.key

        self._cookies[cbtid] = cbt_data

        self.log.debug("New cookie {cbtid} created", cbtid=cbtid)

        # do NOT add the "secure" cookie attribute! "secure" refers to the
        # scheme of the Web page that triggered the WS, not WS itself!!
        return cbtid, '%s=%s;max-age=%d' % (self._cookie_id_field, cbtid, cbt_data['max_age'])

    def setAuth(self, cbtid, authid, authrole, authmethod, authextra, authrealm):
        """ This is the entry point when the system code wishes 
        """
        cookie_obj = self._cookies.get_cookie_obj(cbtid)
        if not cookie_obj:
            return

        super().setAuth( cbtid, authid, authrole, authmethod, authextra, authrealm)

        cookie = self._cookies[cbtid]
        cookie_obj.update_({
                        'modified': cookie['created'],
                        'max_age': cookie['max_age'],
                        'authid': cookie['authid'],
                        'authrole': cookie['authrole'],
                        'authmethod': cookie['authmethod'],
                        'authrealm': cookie['authrealm'],
                        'authextra': cookie['authextra'],
                    })
        cookie_obj.save_()

