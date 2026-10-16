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

import hashlib
import os
import tempfile
import uuid
from unittest import TestCase

from betamax.fixtures import unittest
from Crypto.Cipher import AES
from sqlcipher3 import dbapi2 as sqlite

from enpassreaderlib import EnpassDB
from enpassreaderlib.enpassreaderlib import Entry
from enpassreaderlib.enpassreaderlibexceptions import EnpassDatabaseError, EnpassDecryptionError

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

    def row(self, password_value, totp_value=None, totp_sensitive=0):
        """Builds a row as returned by the entries query."""
        return {'key': self.key + self.nonce,
                'title': 'title',
                'uuid': self.uuid,
                'password_value': password_value,
                'password_value_hash': None,
                'totp_value': totp_value,
                'totp_value_hash': None,
                'totp_value_sensitive': totp_sensitive}

    def test_password_is_decrypted(self):
        """The password of an entry is decrypted with the key of the entry."""
        entry = Entry(self.row(self.encrypt('s3cret pässword')))
        self.assertEqual(entry.password, 's3cret pässword')

    def test_missing_password_is_none(self):
        """An entry without a password returns None."""
        entry = Entry(self.row(None))
        self.assertIsNone(entry.password)

    def test_sensitive_totp_seed_is_decrypted(self):
        """A totp seed stored in a sensitive field is decrypted with the key of the entry."""
        entry = Entry(self.row(None, self.encrypt('JBSWY3DPEHPK3PXP'), totp_sensitive=1))
        self.assertEqual(entry.totp_seed, 'JBSWY3DPEHPK3PXP')

    def test_plain_totp_seed_is_returned_as_is(self):
        """A totp seed stored in a non sensitive field is returned unchanged."""
        entry = Entry(self.row(None, 'JBSWY3DPEHPK3PXP'))
        self.assertEqual(entry.totp_seed, 'JBSWY3DPEHPK3PXP')

    def test_missing_totp_seed_is_none(self):
        """An entry without a totp seed returns None."""
        entry = Entry(self.row(None))
        self.assertIsNone(entry.totp_seed)

    def tamper(self, value, position):
        """Flips the bits of the hex digit at the position of an encrypted value."""
        return f'{value[:position]}{int(value[position], 16) ^ 0xf:x}{value[position + 1:]}'

    def test_tampered_ciphertext_is_rejected(self):
        """A password whose ciphertext has been modified fails authentication."""
        entry = Entry(self.row(self.tamper(self.encrypt('s3cret'), 0)))
        with self.assertRaises(EnpassDecryptionError):
            _ = entry.password

    def test_tampered_tag_is_rejected(self):
        """A password whose authentication tag has been modified fails authentication."""
        entry = Entry(self.row(self.tamper(self.encrypt('s3cret'), -1)))
        with self.assertRaises(EnpassDecryptionError):
            _ = entry.password

    def test_value_of_another_entry_is_rejected(self):
        """A value moved from another entry fails authentication against the uuid of this entry."""
        value = self.encrypt('s3cret')
        self.uuid = str(uuid.uuid4())
        entry = Entry(self.row(value))
        with self.assertRaises(EnpassDecryptionError):
            _ = entry.password

    def test_truncated_value_is_rejected(self):
        """A value too short to hold an authentication tag fails authentication."""
        entry = Entry(self.row(self.encrypt('s3cret')[-20:]))
        with self.assertRaises(EnpassDecryptionError):
            _ = entry.password

    def test_tampered_sensitive_field_is_rejected(self):
        """A sensitive field whose value has been modified fails authentication."""
        field_row = self.field_row('Password', 'password', 's3cret', sensitive=True)
        field_row['value'] = self.tamper(field_row['value'], 0)
        entry = Entry(self.row(None), [field_row])
        with self.assertRaises(EnpassDecryptionError):
            entry.get_field('password')

    def field_row(self, label, type_, value, sensitive=False):
        """Builds a row as returned by the fields query."""
        return {'item_uuid': self.uuid,
                'label': label,
                'type': type_,
                'value': self.encrypt(value) if sensitive else value,
                'sensitive': int(sensitive)}

    def test_fields(self):
        """Fields are retrieved by label or type and sensitive ones are decrypted."""
        field_rows = [self.field_row('Username', 'username', 'costas'),
                      self.field_row('Password', 'password', 's3cret', sensitive=True),
                      self.field_row('Website', 'url', 'https://one.example'),
                      self.field_row('Backup site', 'url', 'https://two.example'),
                      self.field_row('Security answer', 'text', 'blue', sensitive=True)]
        entry = Entry(self.row(None), field_rows)
        self.assertEqual(entry.field_labels,
                         ['Username', 'Password', 'Website', 'Backup site', 'Security answer'])
        self.assertEqual(entry.get_field('username'), 'costas')
        self.assertEqual(entry.get_field('PASSWORD'), 's3cret')
        self.assertEqual(entry.get_field('security answer'), 'blue')
        self.assertEqual(entry.get_field('url'), 'https://one.example')
        self.assertEqual(entry.get_fields('url'), ['https://one.example', 'https://two.example'])
        self.assertEqual(entry.get_field('backup site'), 'https://two.example')
        self.assertIsNone(entry.get_field('missing'))
        self.assertEqual(entry.get_fields('missing'), [])

    def test_label_takes_precedence_over_type(self):
        """A field whose label matches is preferred over one whose type matches."""
        field_rows = [self.field_row('Primary', 'email', 'one@example.com'),
                      self.field_row('Email', 'text', 'two@example.com')]
        entry = Entry(self.row(None), field_rows)
        self.assertEqual(entry.get_field('email'), 'two@example.com')
        self.assertEqual(entry.get_fields('email'), ['two@example.com'])


class TestEnpassDBFields(TestCase):

    password = 'master password'
    rounds = 1000

    def setUp(self):
        """Creates an sqlcipher database with the enpass layout encrypted the way enpass does."""
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.directory.name, 'vault.enpassdb')
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, self.rounds).hex()[:64]
        self.item_key = os.urandom(32) + os.urandom(12)
        self.uuid = str(uuid.uuid4())
        connection = sqlite.connect(self.database_path)
        # A raw key followed by a salt makes sqlcipher write that salt as the first 16 bytes of the file
        connection.execute(f"PRAGMA key=\"x'{key}{salt.hex()}'\";")
        connection.execute('PRAGMA cipher_compatibility = 3;')
        connection.executescript(
            'CREATE TABLE Identity (version INTEGER);'
            'CREATE TABLE item (uuid TEXT, title TEXT, key BLOB);'
            'CREATE TABLE itemfield (item_uuid TEXT, label TEXT, type TEXT, value TEXT, '
            'sensitive INTEGER, hash TEXT, deleted INTEGER);'
            'INSERT INTO Identity VALUES (6);')
        connection.execute('INSERT INTO item VALUES (?, ?, ?);', (self.uuid, 'Mail', self.item_key))
        connection.executemany('INSERT INTO itemfield VALUES (?, ?, ?, ?, ?, NULL, ?);',
                               [(self.uuid, 'Password', 'password', self.encrypt('s3cret'), 1, 0),
                                (self.uuid, 'One time code', 'totp', self.encrypt('JBSWY3DPEHPK3PXP'), 1, 0),
                                (self.uuid, 'Username', 'username', 'costas', 0, 0),
                                (self.uuid, 'Old username', 'username', 'old', 0, 1)])
        connection.commit()
        connection.close()

    def tearDown(self):
        self.directory.cleanup()

    def encrypt(self, plaintext):
        """Encrypts a value with the item key the way enpass stores it."""
        cipher = AES.new(self.item_key[:32], AES.MODE_GCM, nonce=self.item_key[32:])
        cipher.update(bytearray.fromhex(self.uuid.replace('-', '')))
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return (ciphertext + tag).hex()

    def test_entry_fields_are_loaded(self):
        """Entries retrieved from the database carry their non deleted fields."""
        enpass = EnpassDB(self.database_path, self.password, pbkdf2_rounds=self.rounds)
        for entry in (enpass.get_entry('mail'), enpass.search_entries('ai')[0], enpass.entries[0]):
            self.assertEqual(entry.password, 's3cret')
            self.assertEqual(entry.get_field('password'), 's3cret')
            self.assertEqual(entry.get_field('username'), 'costas')
            self.assertEqual(entry.totp_seed, 'JBSWY3DPEHPK3PXP')
            self.assertEqual(entry.get_field('totp'), 'JBSWY3DPEHPK3PXP')
            self.assertEqual(entry.field_labels, ['Password', 'One time code', 'Username'])
        self.assertIsNone(enpass.get_entry('missing'))

    def test_names_are_not_interpreted_as_sql(self):
        """Names containing sql or like pattern syntax are matched literally."""
        enpass = EnpassDB(self.database_path, self.password, pbkdf2_rounds=self.rounds)
        self.assertIsNone(enpass.get_entry('" OR "1"="1'))
        self.assertEqual(enpass.search_entries('"'), [])
        self.assertEqual(enpass.search_entries('" OR "1"="1'), [])
        self.assertEqual(enpass.search_entries('%'), [])
        self.assertEqual(enpass.search_entries('m_il'), [])
        self.assertEqual(enpass.search_entries('\\'), [])
