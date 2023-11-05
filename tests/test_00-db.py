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

from nexus.domain import db
from nexus.orm import RECORD_CACHE
from nexus.orm.filter import Filter, build_filter

initialize()

def test_db():

    #############################################################
    # TEST BASIC FILTERING
    #############################################################
    junk = {
      'a': 'b',
      'c': 'd',
      'e': 1,
      'f': 3,
      'g': [
        'one',
        'two',
        'three',
      ],
    }
    f = build_filter(['a', '=', 'b'])
    assert f
    assert f(junk)

    assert build_filter(['g','has','one'])(junk)

    assert build_filter([
              'or',
              [
                ['g', 'has', 'one'],
              ]
            ])(junk)

    res = build_filter([
              'or',
              [
                ['g', 'has', 'five'],
              ]
            ])(junk)
    assert not res

    res = build_filter([
              'or',
              [
                ['g', 'has', 'five'],
                ['g', 'has', 'one'],
              ]
            ])(junk)
    assert res

    res = build_filter([
              'and',
              [
                [ 'a', '=', 'b' ],
                [ 'or', [
                  ['g', 'has', 'five'],
                  ['g', 'has', 'one'],
                ]]
              ]
            ])(junk)
    assert res

    res = build_filter([
              'and',
              [
                [ 'a', '=', 'c' ],
                [ 'or', [
                  ['g', 'has', 'five'],
                  ['g', 'has', 'one'],
                ]]
              ]
            ])(junk)
    assert not res

    #############################################################
    # Role Handling
    #############################################################

    # Let's create a basic role
    role_obj = db.roles.create_({
            'role': 'myrole',
        })
    assert role_obj
    assert role_obj.uuid

    # Great, now let's append to that role some permissions
    role_obj.permissions.append(
                    {
                        'uri': 'com.izaber.wamp.*',
                        'perms': 'cp',
                    }
            )
    assert role_obj.permissions
    role_obj.uri_authorizer_(True) # force recalculation
    db.vacuum_()

    # Let's check to see the permissions actually work
    assert role_obj.authorize_('com.izaber.wamp.allowed','call')
    assert not role_obj.authorize_('com.izaber.wamp','call')
    assert not role_obj.authorize_('com.izaber.denyme','call')
    assert not role_obj.authorize_('com.izaber.wamp.notallowed','subscribe')

    # Now let's rename the role
    role_obj.role = 'newrolename'
    role_obj.save_()
    db.vacuum_()
    role_obj.uri_authorizer_(True) # force recalculation

    # Check to see how it works out when we double up on the permissions
    role_obj.permissions.append(
                    {
                        'uri': 'com.izaber.wamp.*',
                        'perms': 'cp',
                    }
            )
    print(role_obj.permissions)
    assert role_obj.permissions
    db.vacuum_()
    role_obj.uri_authorizer_(True) # force recalculation


    ######################################################
    # users
    ######################################################

    # Let's create a new role via the DB
    user_obj = db.create(
                    '%root',
                    'users',
                    {
                        'login': 'testuser',
                        'role': 'frontend',
                    }
                )
    assert user_obj
    assert user_obj.uuid
    assert user_obj.name is None


    # Amend the user
    test_name = 'TEST NAME'
    db.update( [user_obj.uuid], { 'name': test_name })
    assert user_obj.name == test_name

    # Can we find the user?
    query_res = db.query('users',[['login','=','testuser']])
    assert query_res
    assert len(query_res['records']) == 1
    assert query_res['records'][0] == user_obj

    # Let's create a bunch of users
    new_users = []
    for i in range(100):
            new_user_obj = db.create(
                            '%root',
                            'users',
                            {
                                'login': f"testuser{i}",
                                'role': 'frontend',
                            }
                        )
            assert new_user_obj
            assert new_user_obj.uuid
            new_users.append(new_user_obj)

    # Then remove the new user
    db.delete([user_obj.uuid])

    # So does it still exist?
    query_res = db.query('users',[['login','=','testuser']])
    assert query_res
    assert len(query_res['records']) == 0

    # However, let's see what happens if we search unbounded
    query_res = db.query('users',sort=[['login','desc']])
    assert query_res
    records = query_res['records']
    assert len(records) == 100
    assert query_res['hits'] == 100

    # Ensure sort works properly
    prev_login = records[0].login
    for rec in records[1:]:
        assert prev_login > rec.login
        prev_login = rec.login

    # What about paging?
    paged_query_res = db.query('users',limit=10,page_index=2,sort=[['login','desc']])
    assert paged_query_res
    paged_records = paged_query_res['records']
    assert len(paged_records) == 10
    assert paged_query_res['hits'] == 100

    # Ensure sort works properly
    prev_login = paged_records[0].login
    for rec in paged_records[1:]:
        assert prev_login > rec.login
        prev_login = rec.login

    # Do we start from the correct place?
    assert paged_records[0] == records[20]

    # Most of the user are all 'frontend' which is great
    # to test authenticated ORM actions
    test_user = paged_records[0]
    results = db.query_authorized(
                            test_user.login,
                            'users',
                        )
    assert results
    assert results['hits'] == 1

    # And make sure we can't elevate ourselves to trust
    assert test_user.name != test_name

    db.update_authorized(
                        test_user.login,
                        [ test_user.uuid ],
                        { 'role': 'trust', 'name': test_name }
                    )
    assert test_user.role == 'frontend'
    assert test_user.name == test_name

    with pytest.raises(PermissionError):
        db.delete_authorized( test_user.login, [ test_user.uuid ] )

    with pytest.raises(PermissionError):
        db.create_authorized( test_user.login, '%root', 'users', {
                                    'login': 'root',
                                    'role': 'trust'
                                })

    # Can we add API Keys for ourself?
    key_obj = db.create_authorized( test_user.login, test_user.uuid, 'apikeys', {
                                    'description': 'test generated key'
                                })
    assert key_obj
    assert key_obj.key

    # No other user can find it right?
    test_user2 = paged_records[1]
    paged_query_res = db.query_authorized(test_user2.login, 'apikeys')
    assert paged_query_res
    assert paged_query_res['hits'] == 0

    # And user 2 can't delete it right?
    print("--- TRYING TO DELETE:", key_obj.uuid)
    with pytest.raises(PermissionError):
        db.delete_authorized( test_user2.login, [key_obj.uuid] )

    # However the creating user can delete, right?
    db.delete_authorized( test_user.login, [key_obj.uuid] )

    ######################################################
    # Database maintenance
    ######################################################

    # Alright, let's just do a quick cleanup which shouldn't cause
    # any issues
    result = db.reindex_uuids()
    assert result['status'] == 'OK'

    # Let's create a link to something that doesn't exist
    fake_uuid = user_obj.uuid
    db.link(fake_uuid, user_obj.yaml_fpath_)
    result = db.reindex_uuids()
    assert result['actions']
    assert len(result['actions']) == 1

    # Rerunning it should leave us clear
    result = db.reindex_uuids()
    assert not result['actions']

    # Let's copy a record to force the reindex to assign a new
    # uuid
    test_user = new_users[0]
    ownership_path = test_user.ownership_path_resolve_(
                            test_user._key_value,
                            test_user.parent_
                        )

    source_path = ownership_path.resolve()
    target_path = source_path.parent / "bananas"
    copy_tree(source_path.as_posix(), target_path.as_posix())

    result = db.reindex_uuids()
    assert result['actions']
    assert len(result['actions']) == 1

    # Rerunning it should leave us clear
    result = db.reindex_uuids()
    assert not result['actions']

    # Let's create a symlink that points to a nonexistant file
    new_uuid = db.generate()
    db.link(new_uuid, 'db/users/chocolate/data.yaml')

    # That should flag a change
    result = db.reindex_uuids()
    assert result['actions']
    assert len(result['actions']) == 1

    # Rerunning it should leave us clear
    result = db.reindex_uuids()
    assert not result['actions']

    ######################################################
    # Creating keys with special characters
    # IN some cases such as using ' ' or ':' inside of
    # the keys that gets stored to files, we need to escape
    # the data
    ######################################################

    # Let's copy a record to force the reindex to assign a new
    # uuid
    test_user = new_users[0]
    ownership_path = test_user.ownership_path_resolve_(
                            test_user._key_value,
                            test_user.parent_
                        )

    source_path = ownership_path.resolve()
    target_path = source_path.parent / "ban^20anas"
    copy_tree(source_path.as_posix(), target_path.as_posix())

    result = db.reindex_uuids()
    assert result['actions']
    assert len(result['actions']) == 1

    user2_obj = db.users.get_('ban anas')
    assert user2_obj

    # Then load all the entries
    user_list = db.users.list_()
    assert len(user_list) == 102

    # Let's now create a "broken" filename
    target_path = source_path.parent / "ban:anas"
    copy_tree(source_path.as_posix(), target_path.as_posix())

    user_list = db.users.list_()
    assert len(user_list) == 102

    fixed_path = target_path.parent / r"ban^3aanas"
    shutil.move( target_path, fixed_path )

    result = db.reindex_uuids()
    assert result['actions']
    assert len(result['actions']) == 1

    user_list = db.users.list_()
    assert len(user_list) == 103

    RECORD_CACHE.clear()

    user2_rec = db.users.get_('ban:anas')

    # Now load via uuid
    user2_uuid = user2_rec.uuid
    user3_rec = db.get( user2_uuid )

    assert user3_rec.login == 'ban:anas'

    # Then can we find the record via query?
    query_res = db.query('users',[['login','=','ban anas']])
    assert query_res['hits'] == 1


if __name__ == "__main__":
    test_db()


