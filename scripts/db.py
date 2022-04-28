#!/usr/bin/env python3

import sys
import os
import pathlib

# Setup for proper pathing for libs and data for when the script
# is executed from this directory
dir_path = os.path.dirname(os.path.realpath(__file__))
cwd = pathlib.Path(os.getcwd())
os.chdir(dir_path)
sys.path.insert(1, f"{dir_path}/..")

import nexus.cli

nexus.cli.run(data_path='./data')


