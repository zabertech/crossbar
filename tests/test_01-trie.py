#!/usr/bin/python

import sys
import os
import pathlib
import shutil
import pytest

# Setup for proper pathing for libs and data
dir_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(dir_path)
sys.path.insert(1, f"{dir_path}/../lib")
os.chdir(f"{dir_path}/data")

from nexus.domain.auth.trie import TrieNode

def test_trie():
    tests = [
      # Search        Option A          Option B          Winner
      ['a.b.c.d.e',   'a.b.c.d.e',      'a.b.c.d.e.*',    1],
      ['a.b.c.d.e',   'a.b.c.d.f',      'a.b.c.d.e.*',    3],
      ['a.b.c.d.e.f', 'a.b.c.d.e',      'a.b.c.d.e.*',    2],
      ['a.b.c.d.e',   'a.b.c.d.e',      'a.b.c.d.e.*',    1],
      ['a.b.c.d.e',   'a.b.c.d.*',      'a.b.*',          1],
      ['a.b.c.d.e',   'a.b.c.d./.*/',   'a.b.c.d.e.*',    1],
      ['a.b.c.d.e',   'a.b.c./.*/.e',   'a.b.c.d.e.*',    1],
      ['a.b.c.d.e',   'a.b./.*/.d.e',   'a.b.c.d.*',      1],
      ['a.b.c.d.e',   'a.b.c.d.*',      'a.b./.*/.d.*',   1],
      ['a.b.c.d',     'a./.*/.c.d',     'a./.*/./.*/.d',  1],
      ['a.b.c.d.e',   'a.b./.*/.d.e',   'a.b.c.*',        1],
      ['a.b.c.d',     'a./.*/.c.d',     'a.b./.*/.d',     3],
      ['b',           '*',              'a',              1],
    ]

    for (search_pattern, pattern_a, pattern_b, expected_winner ) in tests:
        trie = TrieNode()

        trie.append(pattern_a,1)
        trie.append(pattern_b,2)
        try:
            matched = trie.match(search_pattern)
            assert matched
            assert matched.data == expected_winner
        except Exception as ex:
            assert expected_winner == 3, f"m:{search_pattern} p1:{pattern_a} p2:{pattern_b} {expected_winner} != 3"

    # Prefix matches
    trie = TrieNode()
    trie.append('a.b.c.*',True)
    matched = trie.match('a.b.c')
    assert not matched

    # Match everything test. A simple '*' should allow everything
    trie = TrieNode()
    trie.append('*',True)
    matched = trie.match('a.b.c')
    assert matched

    # Deep Prefix matches
    trie = TrieNode()
    trie.append('a.b.c.*',True)
    matched = trie.match('a.b.c.d.e.f')
    assert matched
    matched = trie.match('a.b.c.d.e')
    assert matched
    matched = trie.match('a.b.c.d')
    assert matched

    trie.append('a.b.c.f',True)
    matched = trie.match('a.b.c')
    assert not matched

    trie = TrieNode()
    trie.append('a.b.c.d.f',1)
    trie.append('a.b.c.d.e.*',2)
    matched = trie.match('a.b.c.d.e')
    assert not matched

    # We expect an exception if we try and add two rules with the same prefix
    trie = TrieNode()
    trie.append('a.b.c.*','123')
    success = False
    try:
        trie.append('a.b.c.*','123')
    except Exception:
        success = True
    assert success


if __name__ == "__main__":
    test_trie()


