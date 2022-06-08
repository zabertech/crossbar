import schedule
import threading
import traceback
import time

from izaber import config
from izaber.startup import request_initialize, initializer

from nexus.domain import db, controller
from nexus.log import log

class Cron(threading.Thread):

    def run(self):
        while True:
            try:
                schedule.run_pending()
            except Exception as ex:
                log.error(f"Error in cron job thread: {ex}")
                traceback.print_exc()
            time.sleep(1)

cron = Cron()

@initializer('nexus-cron')
def load_config(**options):
    request_initialize('nexus-dir',**options)
    cron.daemon = True
    cron.start()

