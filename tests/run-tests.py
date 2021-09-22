#!/usr/bin/env python

import os
import sys
import pathlib
import subprocess
import re

file_path = pathlib.Path(os.path.realpath(__file__))

base_path = file_path.parent

test_fpaths = list(base_path.glob('test*.py'))
test_fpaths.sort()

tests_count = len(test_fpaths)
tests_seen = 0

for test_fpath in test_fpaths:
    tests_seen += 1
    print("-------------")
    print(f"Running test {test_fpath} {tests_seen}/{tests_count}")
    print("-------------")
    cmd_str = f"{sys.executable} {test_fpath}"
    result = subprocess.call(cmd_str, shell=True)
    if result:
        print(f"Error on test {test_fpath}. You can execute yourself with:\n\n{cmd_str}\n")
        sys.exit(1)
else:
    print("Success!")



