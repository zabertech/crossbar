from autobahn.twisted.wamp import ApplicationSession
from autobahn.wamp.exception import ApplicationError
from autobahn.wamp.types import RegisterOptions, SubscribeOptions

from nexus.constants import WAMP_LOCAL_SUBSCRIPTION_PREFIX, WAMP_LOCAL_REGISTRATION_PREFIX

from twisted.logger import Logger
from twisted.internet.defer import inlineCallbacks

import traceback

__all__ = [
  'wamp_subscribe',
  'wamp_register',
  'BaseComponent',
]

def _wamp_decorate(uri_, method):
    """ Does the actual work of decorating the method so that
        it's recognized by the onJoin for sub/reg
    """
    def decorate(fn):
        # So this is required since for some reason, python thinks that
        # without this forced assignment, that uri is not declared
        # and we get the error:
        # UnboundLocalError: local variable 'uri' referenced before assignment
        # https://stackoverflow.com/questions/29639780
        uri = uri_
        if uri[0] == '.':
            uri = WAMP_LOCAL_SUBSCRIPTION_PREFIX + uri
        if not hasattr(fn, 'wamp'):
            fn.wamp = {
                'subscribe': [],
                'register': [],
            }
        fn.wamp[method].append(uri)
        return fn

    return decorate

def wamp_subscribe(uri, deprecated=False):
    return _wamp_decorate(uri, 'subscribe')

def wamp_register(uri, deprecated=False):
    return _wamp_decorate(uri, 'register')

def wamp_subscription_handler_factory(component, handler, *args, **kwargs):
    def wrap(*args, details=None, **kwargs):
        authid = details.publisher_authid
        try:
            return handler(*args, **kwargs, details=details)
        except PermissionError as ex:
            raise ApplicationError(u"com.izaber.wamp.error.permissiondenied","Permission Denied")
        except ApplicationError as ex:
            component.log.warn(f"----------------------------------------------")
            import traceback
            for l in traceback.format_exc().split('\n'):
                if l: component.log.debug(f"> {l}")
            raise
        except Exception as ex:
            component.log.warn(f"----------------------------------------------")
            component.log.warn(f"Handler Failure for {authid} because '{ex}'"\
                               f"<{type(ex)}>")
            component.log.warn(f"ARGS: {repr(args)}")
            component.log.warn(f"KWARGS: {repr(kwargs)}")
            component.log.warn(f"DETAILS: {repr(details)}")
            raise
    return wrap


def wamp_register_handler_factory(component, handler, *args, **kwargs):
    def wrap(*args, details=None, **kwargs):
        authid = details.caller_authid
        try:
            return handler(*args, **kwargs, details=details)
        except PermissionError as ex:
            raise ApplicationError(u"com.izaber.wamp.error.permissiondenied","Permission Denied")
        except ApplicationError as ex:
            component.log.warn(f"----------------------------------------------")
            import traceback
            for l in traceback.format_exc().split('\n'):
                if l: component.log.debug(f"> {l}")
            raise
        except Exception as ex:
            component.log.warn(f"----------------------------------------------")
            component.log.warn(f"Handler Failure for {authid} because '{ex}'"\
                          f"<{type(ex)}>")
            component.log.warn(f"ARGS: {repr(args)}")
            component.log.warn(f"KWARGS: {repr(kwargs)}")
            component.log.warn(f"DETAILS: {repr(details)}")
            raise
    return wrap

class BaseComponent(ApplicationSession):
    log = Logger()

    @inlineCallbacks
    def onJoin(self, details):
        for attr in dir(self):
            handler = getattr(self, attr)

            if not handler \
            or not callable(handler) \
            or not hasattr(handler, 'wamp'):
                continue

            try:
                wamp = handler.wamp
                if wamp['subscribe']:
                    for uri in wamp['subscribe']:
                        yield self.subscribe(
                            wamp_subscription_handler_factory(self, handler),
                            uri,
                            SubscribeOptions(details=True)
                        )

                if wamp['register']:
                    for uri in wamp['register']:
                        yield self.register(
                            wamp_register_handler_factory(self, handler),
                            uri,
                            RegisterOptions(
                                details=True,
                                force_reregister=True,
                            )
                        )

            except Exception as ex:
                self.log.error(f"Unable to register {attr}: {ex}")
