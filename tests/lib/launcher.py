import os
import socket
import time
import datetime
import pathlib
import subprocess

# Setup for proper pathing for libs and data
LIB_PATH = pathlib.Path(__file__).resolve().parent
TEST_PATH = LIB_PATH.parent
DATA_PATH = TEST_PATH / 'data'
LOG_FPATH = DATA_PATH  / 'node.log'

LOG_READ = 0

def nexus_log_data():
    """ Returns information found in the nexus log since the last
        request
    """
    global LOG_READ

    if not LOG_FPATH.exists():
        return ''

    with LOG_FPATH.open('r') as f:
        f.seek(LOG_READ)
        data = f.read()
        LOG_READ = f.tell()

    return data

def nexus_is_up():
    location = ("127.0.0.1", 8282)
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if a_socket.connect_ex(location) == 0:
        return True
    return False

def launch_nexus(file_log=None, **kwargs):
    """ This starts a copy of nexus on the local server
    """
    global LOG_READ

    # Huh, if nexus is up, I guess we'll try and kill it
    if nexus_is_up():
        subprocess.Popen(['pkill', '-9', 'crossbar'])

    # If there exists already a log file, find out the c^Hmtime and
    # move it out of the way
    if LOG_FPATH.exists():
        ctime = LOG_FPATH.stat().st_ctime
        ctimestamp = datetime.datetime.fromtimestamp(ctime)
        LOG_FPATH.rename(
          LOG_FPATH.parent / f"node-{ctimestamp:%Y%m%d-%H%M%S}.log"
        )

    # How we're going to launch crossbar
    cx_env = os.environ
    log_level = cx_env.get('LOG_LEVEL', 'info')
    launch_args = [
                    "crossbar",
                    "start",
                    "--loglevel", log_level,
                ]

    # If we're logging to file, setup the flag properly
    if 'NO_LOG_FILE' in cx_env:
        pass
    elif 'LOG_FILE' in cx_env:
        launch_args.extend([
                    "--logtofile",
                    "--logdir", cx_env['LOG_FILE'],
                ])
    elif file_log or file_log is None:
        launch_args.extend([
                    "--logtofile",
                    "--logdir", str(DATA_PATH),
                ])

    # Launch the crossbar server and it will log to LOG_FPATH
    cx_env['PYTHONPATH'] = str(LIB_PATH)
    cx_process =  subprocess.Popen(launch_args, env=cx_env, **kwargs)

    # Wait till port 8282 is open. Give up after 60 seconds
    for i in range(60):
        time.sleep(1)
        if nexus_is_up():
            break
    else:
        print(f"Port is not open. Giving up though")

    return cx_process

