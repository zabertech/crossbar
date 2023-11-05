#!/usr/bin/python

import sys
import os
import pathlib
import shutil
import pytest
from distutils.dir_util import copy_tree

# Setup for proper pathing for libs and data
dir_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(dir_path)
sys.path.insert(1, f"{dir_path}/../lib")
os.chdir(f"{dir_path}/data")

# Whack the data nexus.domain for now
cpath = pathlib.Path('db')
if cpath.exists():
    shutil.rmtree(cpath)
cpath.mkdir(parents=True,exist_ok=True)

from izaber import initialize, config

from nexus.orm import *

initialize()

YAML_SCHEMA = """
version: 1.0

field1:
    default: "a"
    help: "some sort of help text"

field2:
    default: "b"
    help: |-
        Some
        multiline
        text here
        line 4
        line 5

"""

YAML_WITH_COMMENT = """
# COMMENTX
hello: "world"
"""

def test_db():
    """ In this test, we verify that the yaml generation from the schema is
        working properly
    """

    # Create an initial schema
    columns = NexusSchema(
        version = 1.1,
        field1 = NexusField('Field1', default=None),
        field2 = NexusField('Field2', default=2),
        field3 = NexusField('Field3', default=3),
    )

    # Convert the column definition into a ruamel YAML instance
    test_yaml = columns.yaml()
    assert test_yaml
    assert test_yaml['field1'] is None
    assert test_yaml['field2'] == 2
    assert test_yaml['field3'] == 3

    # Now let's create an upgraded schema
    columns2 = NexusSchema(
        version = 1.2,
        field1 = NexusField('Field1', default=100),
        field2 = NexusField('Field2', default=100),
        field3 = NexusField('Field3', default=100),
        field4 = NexusField('Field4', default=4),
    )

    # This will "migrate" the yaml over to the new version
    migrated_yaml = columns2.migrate(test_yaml)
    assert migrated_yaml
    assert migrated_yaml['field1'] is None
    assert migrated_yaml['field2'] == 2
    assert migrated_yaml['field3'] == 3
    assert migrated_yaml['field4'] == 4
    assert migrated_yaml['version'] == 1.2

    # This should convert a YAML template file into a data structure
    fromstr_columns = NexusSchema.from_yaml(YAML_SCHEMA)
    fromstr_yaml = fromstr_columns.yaml()
    assert fromstr_yaml
    assert fromstr_yaml['field1'] == "a"
    assert fromstr_yaml['field2'] == "b"

    '''
    Can we add a value to this output?
    This is a slightly weird issue where it's possible to create a yaml value
    with a comment at the top. It is also possible to assign this value to an
    existing yaml instance key. Unfortunately, since comment handling gets weird
    right now the original comment will be lost.
    
    So we can have something like:

    ```yaml
    version: 1
    value: null
    ```

    We can then have a value like this:

    ```yaml
    # Sets the speed of the widget
    speed: 9001
    ```

    If we try and assign this second value to the first under `value` we get:

    ```yaml
    version: 1
    value:
        speed: 9001
    ```

    Data wise it's correct but the comment "Sets the speed..." gets lost. This isn't
    a big deal since the data still is present but it's a bit annoying. This test
    is here so that when we support the transfer of comments, we can then amend the
    user_metadata_set and user_metadata_get test code
    '''
    test_yaml_value = yaml_load(YAML_WITH_COMMENT)
    assert test_yaml_value["hello"] == "world"

    test_yaml_str = yaml_dumps(test_yaml_value)
    assert 'COMMENTX' in test_yaml_str

    test_yaml['field1'] = test_yaml_value
    assert test_yaml["field1"]["hello"] == "world"

    # Now test that the comment made its way over
    yaml_str = yaml_dumps(test_yaml)
    assert 'COMMENTX' not in yaml_str


if __name__ == "__main__":
    test_db()

