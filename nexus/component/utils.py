from nexus.component.base import *

from izaber import initialize, config
from izaber.email import mailer

class UtilitiesComponent(BaseComponent):

    @wamp_register('.email.send', deprecated=True)
    def email_send(self, recipient, subject, message, options=None, details=None):

        # Write some fancy options handling instead of just
        # hard coded email send
        sender = "gizmo@zaber.com"
        mailer.basic_send(sender, [recipient], subject, message)

initialize('nexus')
