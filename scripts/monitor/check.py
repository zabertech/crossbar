#!/usr/bin/python


"""
Usage:
  check.py [options]

Options:
  -h --help     Show help
  -e --environment=<env-key>  izaber.yaml Environment to use [default: default]

Details:

  ~/izaber.yaml should have the something like the following. Note that it is important to use the
  `gizmo` account as it is one of the only accounts with `trust` role on the server

    default:
      debug: false
      log:
          level: 100
      email:
          from: test@zaber.com
          host: localhost
      paths:
          path: '~'
      wamp:
          connection:
              url: 'wss://nexus.izaber.com/ws'
              username: "gizmo"
              password: PASSWORD @ https://cv.izaber.com/vsCredential/show/428

      nexus_monitor:
        required:
          - match: "com.izaber.wamp.attendance.getCalendar"
          - match: "com.izaber.wamp.attendance.getEveryoneAwayStatus"
          - match: "com.izaber.wamp.dashboard:live:customerItems.get"
          - match: "com.izaber.wamp.dashboard:live:customerItems.refresh"
          - match: "com.izaber.wamp.dashboard:live:dashboardRegistry.get"
          - match: "com.izaber.wamp.dashboard:live:dashboardRegistry.register"
          - match: "com.izaber.wamp.dashboard:live:dashboardRegistry.unregister"
          - match: "com.izaber.wamp.dashboard:live:redmine.addWatcherToIssues"
          - match: "com.izaber.wamp.dashboard:live:redmine.getAllCustomFields"
          - match: "com.izaber.wamp.dashboard:live:redmine.getAllUsers"
          - match: "com.izaber.wamp.dashboard:live:redmine.getCustomFieldsForProject"
          - match: "com.izaber.wamp.dashboard:live:redmine.getIssueList"
          - match: "com.izaber.wamp.dashboard:live:redmine.getIssues"
          - match: "com.izaber.wamp.dashboard:live:redmine.getProjectList"
          - match: "com.izaber.wamp.dashboard:live:redmine.getUrl"
          - match: "com.izaber.wamp.graphs.product_graph_consumption"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.get_branch_list"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.get_commit_list"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.get_parameters"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.get_script_list"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.get_stage_clients"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.open_network_port"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.reboot"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.release_test"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.resume_from_log_file"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.resume_test"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.send_generic_command"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.start_test"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.stop_test"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.update_parameters"
          - match: "com.izaber.wamp.mech.testing.ltd.backend.update_triggers"
          - match: "com.izaber.wamp.notification.digest.get"
          - match: "com.izaber.wamp.notification.digest.remove"
          - match: "com.izaber.wamp.notification.digest.set"
          - match: "com.izaber.wamp.notification.router.allGenerators"
          - match: "com.izaber.wamp.notification.router.generators"
          - match: "com.izaber.wamp.notification.router.get"
          - match: "com.izaber.wamp.notification.router.registerDestination"
          - match: "com.izaber.wamp.notification.router.registerGenerator"
          - match: "com.izaber.wamp.notification.router.registerTopic"
          - match: "com.izaber.wamp.notification.router.update"
          - match: "com.izaber.wamp.pdf.htmlToPdf"
          - match: "com.izaber.wamp.scriptsvc.public.run"
          - match: "com.izaber.wamp.scriptsvc.public.scripts"
          - match: "com.izaber.wamp.system.admin.password.changepass"
          - match: "com.izaber.wamp.weborders.server.credit.card.decrypt.call"
          - match: "com.izaber.wamp.weborders.server.credit.card.save.call"
          - match: "com.izaber.wamp.zerp:live:"
          - match: "com.izaber.wamp.zerp:sandbox:"
          - match: "com.izaber.wamp.zerp:zandbox-sensitive:"
          - match: "com.izaber.wamp.zerp:sandbox2:"
          - match: "com.izaber.wamp.system.authenticator"
          - match: "com.izaber.wamp.system.authorizer"
          - match: "com.izaber.wamp.system.reauthenticate"
          - match: "com.izaber.wamp.system.is_reauthenticated"
          - match: "com.izaber.wamp.system.extend_reauthenticate"
          - match: "com.izaber.wamp.system.refresh_authorizer"
          - match: "com.izaber.wamp.system.api_key.authorizer"
          - match: "com.izaber.wamp.api_key.list_keys"
          - match: "com.izaber.wamp.api_key.create_key"
          - match: "com.izaber.wamp.api_key.delete_key"
          - match: "com.izaber.wamp.directory.authenticate"
          - match: "com.izaber.wamp.directory.users"
          - match: "com.izaber.wamp.directory.groups"
          - match: "com.izaber.wamp.email.send"
          - match: "com.izaber.wamp.system.preference.get"
          - match: "com.izaber.wamp.system.preference.set"
          - match: "com.izaber.wamp.system.preference.remove"
          - match: "com.izaber.wamp.system.preference.filter_preference"

        ignore:
          - pattern: 'com.izaber.wamp.mech.testing.ltd.\w\w:\w\w:\w\w:\w\w:\w\w:\w\w..*'



"""

import re
import os
import sys
import attr
import types

import docopt

import swampyer

from izaber import initialize, config
from izaber.wamp import wamp
from izaber.paths import paths
from izaber.templates import parse, parsestr

VERSION = '1.0.20200511'

@attr.s
class MonitorApp:
    wamp = attr.ib()
    config = attr.ib()

    # Keeps track of information regarding sessions on the system
    # FIXME: If this is goin got be a long-running app, ensure
    # this gets flushed once in awhile or kept up to date via
    # session meta-events
    session_cache = {}

    # This keeps a track of the existing registrations
    # on the nexus server
    registered = {}

    def start(self):
        """ Initialize the datastructures and relevant steps for
            the checker services
        """
        self.registered = self.query_registered()
        self.services = self.query_services()

    def query_registered(self):
        """ Requests nexus for the current list of registered URIs
        """
        data = self.wamp.call('wamp.registration.list')
        registered = []
        for match_type, reg_ids in data.items():
            for reg_id in reg_ids:
                reg_data = self.wamp.call('wamp.registration.get',reg_id)
                uri = reg_data.get('uri')

                # Get information on who are listed as callees
                call_info = self.wamp.call('wamp.registration.list_callees',reg_id)
                reg_data['callees'] = []

                for session_id in call_info:
                    if session_id not in self.session_cache:
                        session_info = self.wamp.call('wamp.session.get', session_id)

                        transport_info = session_info.get('transport',{}) or {}

                        headers = transport_info.get('http_headers_received', {}) or {}
                        peer = headers.get('x-forwarded-for') or transport_info.get('peer','INTERNAL')
                        session_info['peer'] = peer

                        self.session_cache[session_id] = session_info

                    session_info = self.session_cache[session_id] or {}
                    reg_data['callees'].append(session_info)

                    """
                    transport_info = session_info.get('transport',{}) or {}
                    peer = transport_info.get('peer','INTERNAL')
                    authid = session_info.get('authid','None')
                    print(f"{reg_type},{reg_info['uri']},{authid},{peer}")
                    """

                registered.append(reg_data)
        return registered

    def check(self):
        """
        """

        # All the URIs we expect to see on the server
        uris_required = self.config.required
        uris_required_seen = []

        # Then a list of all the ignore matches. We do not
        # clobber so we won't worry about things here
        uris_ignore = self.config.ignore

        # Then a list of all the URIs
        # This creates a dict that should be used thus:
        # {
        #   <obj reg-data>: boolean, # False if not matched, True if matched
        # }
        registrations = self.query_registered()
        registrations_handled = []

        # Pass through all registered URIs and match them to rules
        for reg_data in registrations:

            # Check if the URI matches of the required entries
            unmatched_rules = filter(
                                    lambda r: r not in uris_required_seen,
                                    uris_required
                                )

            for uri_rule in unmatched_rules:
                if self.test_match(uri_rule, reg_data):
                    registrations_handled.append(reg_data)
                    uris_required_seen.append(uri_rule)
                    break

            for ignore_rule in uris_ignore:
                if self.test_match(ignore_rule, reg_data):
                    registrations_handled.append(reg_data)
                    break

        # Now we can determine which registrations are missing
        unmatched_rules = filter( lambda r: r not in uris_required_seen, uris_required )

        # And the registrations that are unknown
        unmatched_registrations = filter( lambda r: r not in registrations_handled, registrations )

        # No errors? Awesome, just return
        if not unmatched_rules and unmatched_registrations:
            return

        return {
            'unmatched_rules': list(unmatched_rules),
            'unmatched_registrations': list(unmatched_registrations)
        }

    def test_match(self, uri_rule, reg_data):
        """ Compares the rule against the registration data and
            returns a True value if it matches
        """

        uri = reg_data['uri']

        # Check if the registration even matches the rules
        if 'pattern' in uri_rule:
            pattern = uri_rule['pattern']
            if not re.match(pattern,uri):
                return False
        elif 'match' in uri_rule:
            if uri != uri_rule['match']:
                return False
        else:
            raise Exception(f'No known URI match scheme used in rule {uri_rule}')

        # Went through the gauntlet and matched so we'll say yes
        return True

def main(args):
    environment = args['--environment']

    initialize('wamp-scanner', environment=environment)

    # This strips the com.izaber.wamp prefix that the system will
    # automatically apply
    wamp.wamp.uri_base = ''
    app = MonitorApp(
                wamp=wamp.wamp,
                config=config.nexus_monitor
            )

    check_errors = app.check()

    if check_errors:
        print(parse('templates/check.txt',**check_errors))
        sys.exit(2)
    else:
        print("OK!")
        sys.exit(0)



if __name__ == '__main__':
    args = docopt.docopt(__doc__, version=VERSION)
    main(args)



