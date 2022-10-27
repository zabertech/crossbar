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









