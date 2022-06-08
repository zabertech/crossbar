from autobahn.twisted.wamp import ApplicationSession
from autobahn.wamp.exception import ApplicationError
from autobahn.wamp.types import RegisterOptions, SubscribeOptions

from nexus.constants import WAMP_LOCAL_SUBSCRIPTION_PREFIX, WAMP_LOCAL_REGISTRATION_PREFIX
from nexus.log import log

from twisted.logger import Logger
from twisted.internet.defer import inlineCallbacks

import traceback

__all__ = [
  'wamp_subscribe',
  'wamp_register',
  'BaseComponent',
  'RequireDocumentationPermissionError',
  'InvalidLoginPermissionError',
  'RequireRosterOpsPermissionError',
  'RequireRosterQueryPermissionError',
]

class InvalidLoginPermissionError(PermissionError):
    pass

class RequireDocumentationPermissionError(PermissionError):
    pass

class RequireRosterOpsPermissionError(PermissionError):
    pass

class RequireRosterQueryPermissionError(PermissionError):
    pass

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
            log.error(ex)
            log.error(traceback.format_exc())
            # The preference is to not simply hide the error, however, it seems that
            # by throwing the error, it stops the thread altogether which then causes
            # authenticate to fail. That's even less desireable so we just fail out
            # silently
            #raise ApplicationError(u"com.izaber.wamp.error.permissiondenied","Permission Denied")
            return
        except ApplicationError as ex:
            log.error(ex)
            log.error(traceback.format_exc())
            # The preference is to not simply hide the error, however, it seems that
            # by throwing the error, it stops the thread altogether which then causes
            # authenticate to fail. That's even less desireable so we just fail out
            # silently
            return
        except Exception as ex:
            log.error(f"Subcription Handler Failure for {authid} because '{ex}'"\
                     f"<{type(ex)}>")
            log.error(f"ARGS: {repr(args)}")
            log.error(f"KWARGS: {repr(kwargs)}")
            log.error(f"DETAILS: {repr(details)}")
            log.error(f"TRACEBACK: {traceback.format_exc()}")
            # The preference is to not simply hide the error, however, it seems that
            # by throwing the error, it stops the thread altogether which then causes
            # authenticate to fail. That's even less desireable so we just fail out
            # silently
            # raise ApplicationError("com.izaber.wamp.error", f"{ex}")
            return
    return wrap


def wamp_register_handler_factory(component, handler, *args, **kwargs):
    def wrap(*args, details=None, **kwargs):
        authid = details.caller_authid
        try:
            return handler(*args, **kwargs, details=details)
        except RequireDocumentationPermissionError as ex:
            raise ApplicationError("com.izaber.wamp.error.requiredocumentation", str(ex))
        except PermissionError as ex:
            raise ApplicationError("com.izaber.wamp.error.permissiondenied", "Permission Denied")
        except InvalidLoginPermissionError as ex:
            raise ApplicationError('com.izaber.wamp.error.invalidlogin','Invalid Login')
        except ApplicationError as ex:
            log.warning(f"Invocation Error: <{ex}>")
            log.warning(traceback.format_exc())
            raise

        # Switch all errors to something that we can handle
        except Exception as ex:
            log.warning(f"Invocation Failure for {authid} because <{ex}>"\
                f"<{type(ex)}>")
            log.warning(f"ARGS: {repr(args)}")
            log.warning(f"KWARGS: {repr(kwargs)}")
            log.warning(f"DETAILS: {repr(details)}")
            log.error(f"TRACEBACK: {traceback.format_exc()}")
            raise ApplicationError("com.izaber.wamp.error", str(ex))
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
                        self.log.info(f"Subscribing to {uri}")
                        yield self.subscribe(
                            wamp_subscription_handler_factory(self, handler),
                            uri,
                            SubscribeOptions(details=True)
                        )

                if wamp['register']:
                    for uri in wamp['register']:
                        self.log.info(f"Registering {uri}")
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
