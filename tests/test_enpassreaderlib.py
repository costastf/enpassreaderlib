#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_enpassreaderlib.py
#
# Copyright 2021 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
test_enpassreaderlib
----------------------------------
Tests for `enpassreaderlib` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import os
import tempfile
import uuid
from unittest import TestCase

from betamax.fixtures import unittest
from Crypto.Cipher import AES

from enpassreaderlib import EnpassDB
from enpassreaderlib.enpassreaderlib import Entry
from enpassreaderlib.enpassreaderlibexceptions import EnpassDatabaseError

__author__ = '''Costas Tyfoxylos <costas.tyf@gmail.com>'''
__docformat__ = '''google'''
__date__ = '''25-03-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<costas.tyf@gmail.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class TestEnpassreaderlib(unittest.BetamaxTestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        pass

    def tearDown(self):
        """
        Test tear down

        This is where you should tear down what you've setup in setUp before. This method is called after every test.
        """
        pass

    def test_invalid_database_raises(self):
        """A file that is not an enpass database raises EnpassDatabaseError."""
        with tempfile.NamedTemporaryFile(suffix='.db') as database:
            database.write(b'not an enpass database' * 64)
            database.flush()
            with self.assertRaises(EnpassDatabaseError):
                EnpassDB(database.name, 'password', pbkdf2_rounds=1)


class TestEntry(TestCase):

    def setUp(self):
        """Creates an item key and uuid the way enpass stores them."""
        self.key = os.urandom(32)
        self.nonce = os.urandom(12)
        self.uuid = str(uuid.uuid4())

    def encrypt(self, plaintext):
        """Encrypts a value the way enpass stores it, hex of ciphertext followed by the tag."""
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        cipher.update(bytearray.fromhex(self.uuid.replace('-', '')))
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return (ciphertext + tag).hex()

    def row(self, password_value):
        """Builds a row as returned by the entries query."""
        return {'key': self.key + self.nonce,
                'title': 'title',
                'uuid': self.uuid,
                'password_value': password_value,
                'password_value_hash': None,
                'totp_value': None,
                'totp_value_hash': None}

    def test_password_is_decrypted(self):
        """The password of an entry is decrypted with the key of the entry."""
        entry = Entry(self.row(self.encrypt('s3cret pässword')))
        self.assertEqual(entry.password, 's3cret pässword')

    def test_missing_password_is_none(self):
        """An entry without a password returns None."""
        entry = Entry(self.row(None))
        self.assertIsNone(entry.password)
