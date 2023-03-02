#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: enpassreaderlib.py
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
Main code for enpassreaderlib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import binascii
import hashlib
import logging

from pathlib import Path

from Crypto.Cipher import AES
from pysqlcipher3 import dbapi2 as sqlite

from .enpassreaderlibexceptions import EnpassDatabaseError

__author__ = '''Costas Tyfoxylos <costas.tyf@gmail.com>'''
__docformat__ = '''google'''
__date__ = '''25-03-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<costas.tyf@gmail.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


# This is the main prefix used for logging
LOGGER_BASENAME = 'enpassreaderlib'
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class EnpassDB:
    """Manages the database object exposing useful methods to interact with it."""

    def __init__(self, database_path, password, keyfile=None, pbkdf2_rounds=100_000):
        self._database_path = database_path
        self._password = password.encode('utf-8')
        self._keyfile = keyfile
        self.pbkdf2_rounds = pbkdf2_rounds
        self._master_password = None
        self._cipher_key = None
        self._connection, self._cursor = self._authenticate()

    @property
    def _retrieve_all_query(self):
        field_types = ['password', 'totp']
        return ('SELECT '
                'i.title, '
                'i.uuid, '
                'i.key, '
                'if_password.value as password_value, '
                'if_password.hash as password_value_hash, '
                'if_totp.value as totp_value, '
                'if_totp.hash as totp_value_hash '
                'FROM item i ' + ''.join([(f'LEFT JOIN '
                                           f'(SELECT item_uuid, type, value, hash '
                                           f'FROM itemfield WHERE type = "{type_}") if_{type_} '
                                           f'ON i.uuid = if_{type_}.item_uuid ') for type_ in field_types]))

    @property
    def master_password(self):
        """The master password calculated along with the key if provided else the password provided.

        Returns:
            master_password (bytearray): The master password to decrypt the database.

        """
        if self._master_password is None:
            if self._keyfile:
                key_hex_xml = Path(self._keyfile).read_bytes()
                key_bytes = binascii.unhexlify(key_hex_xml[slice(5, -6)])
                self._password = self._password + key_bytes
            self._master_password = self._password
        return self._master_password

    @property
    def cipher_key(self):
        """The cipher key to decrypt entries in the database.

        Returns:
            cipher_key (string): The cipher key to decrypt the database entries.

        """
        if self._cipher_key is None:
            # The first 16 bytes of the database file are used as salt
            with open(self._database_path, "rb") as db:
                enpass_db_salt = db.read(16)
            # The database key is derived from the master password
            # and the database salt with 100k iterations of PBKDF2-HMAC-SHA512
            enpass_db_key = hashlib.pbkdf2_hmac("sha512", self.master_password, enpass_db_salt, self.pbkdf2_rounds)
            # The raw key for the sqlcipher database is given
            # by the first 64 characters of the hex-encoded key
            self._cipher_key = enpass_db_key.hex()[:64]
        return self._cipher_key

    def _authenticate(self):
        try:
            connection = sqlite.connect(self._database_path)
            cursor = connection.cursor()
            cursor.row_factory = sqlite.Row
            cursor.execute(f"PRAGMA key=\"x'{self.cipher_key}'\";")
            cursor.execute('PRAGMA cipher_compatibility = 3;')
            cursor.execute('SELECT * FROM Identity;').fetchone()
        except sqlite.DatabaseError:
            raise EnpassDatabaseError('Either the master password or the key file provided cannot decrypt '
                                      'the database, or it is not a valid enpass 6 encrypted database.') from None
        return connection, cursor

    def _query(self, query):
        self._cursor.execute(query)
        # If you deleted an item from Enpass, it stays in the database, but the
        # entries are cleared so only entries with nonce are valid entries
        return [row for row in self._cursor if row["key"][32:]]

    @property
    def entries(self):
        """All the entries in the database.

        Returns:
            entries (list): The password entries in the database.

        """
        return [Entry(row) for row in self._query(f'{self._retrieve_all_query};')]

    def get_entry(self, name):
        """Retrieves a single entry matching the name.

        Args:
            name: The name of the password entry to retrieve.

        Returns:
            entry (Entry): A password entry object if match found else None.

        """
        query = f'{self._retrieve_all_query} WHERE lower(i.title) = \"{name.lower()}\";'
        row = next((row for row in self._query(query)),
                   None)
        if row is None:
            return row
        return Entry(row)

    def search_entries(self, name):
        """Retrieves any entry that matches the name provided (fuzzy matching).

        Args:
            name: The name to search the password entries for.

        Returns:
            entries (list): A list of password entries matching the fuzzy search for the given name.

        """
        query = f'{self._retrieve_all_query} WHERE lower(i.title) LIKE \"%{name.lower()}%\";'
        return [Entry(row) for row in self._query(query)]


class Entry:
    """Models a password entry and exposes some useful attributes about it."""

    def __init__(self, database_row):
        # The key object is saved in binary from and actually consists of the
        # AES key (32 bytes) and a nonce (12 bytes) for GCM
        self.key = database_row["key"][:32]
        self.nonce = database_row["key"][32:]
        self.title = database_row["title"]
        self._password_value = database_row["password_value"]
        self._password_hash = database_row["password_value_hash"]
        self.uuid = database_row["uuid"]
        self._totp_hash = database_row["totp_value_hash"]
        self._totp = database_row["totp_value"]
        self.header = self.uuid.replace("-", "")
        self._password = None

    @property
    def password(self):
        """The plaintext password of the entry.

        Returns:
            password (text): The plaintext password of the entry.

        """
        if self._password is None:
            # The value object holds the ciphertext (same length as plaintext) +
            # (authentication) tag (16 bytes) and is stored in hex
            ciphertext = bytearray.fromhex(self._password_value[:len(self._password_value) - 32])
            # Now we can initialize, decrypt the ciphertext and verify the AAD.
            # You can compare the SHA-1 output with the value stored in the db
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
            cipher.update(bytearray.fromhex(self.header))
            self._password = cipher.decrypt(ciphertext).decode("utf-8")
        return self._password

    @property
    def totp_seed(self):
        return self._totp
