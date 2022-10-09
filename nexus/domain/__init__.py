from izaber.startup import request_initialize, initializer
from izaber import config

from nexus.domain.db import db
from nexus.domain.controller import Controller
from nexus.domain.ldap import ldap

controller = Controller()

@initializer('nexus-dir')
def load_config(**options):
    request_initialize('nexus-db',**options)
    request_initialize('nexus-ldap',**options)
    controller.load_config()

    # If the db has disable_start_reset to a truthy value, we ignore the usual process
    # of "cleanup" where stuff like registrations are all marked invalid. This is
    # useful if we're doing multiple servers and doing low downtime transitions
    if config.nexus.db.get('disable_startup_reset'):
        return

    # Mark all registrations as unregistered
    for uri_rec in db.uris:
        uri_rec.mark_unregistered_(True)









