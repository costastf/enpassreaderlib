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
from sqlcipher3 import dbapi2 as sqlite

from .enpassreaderlibexceptions import EnpassDatabaseError, EnpassDecryptionError

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

    def __init__(self, database_path, password, keyfile=None, pbkdf2_rounds=320_000):
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
                'if_totp.hash as totp_value_hash, '
                'if_totp.sensitive as totp_value_sensitive '
                'FROM item i ' + ''.join([(f'LEFT JOIN '
                                           f'(SELECT item_uuid, type, value, hash, sensitive '
                                           f"FROM itemfield WHERE type = '{type_}') if_{type_} "
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
                key_bytes = binascii.unhexlify(key_hex_xml[slice(5, -6)])  # noqa
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
        database_path = Path(self._database_path)
        if not database_path.is_file():
            raise EnpassDatabaseError(f'The database file {database_path} does not exist.')
        # Opened read only so the vault can never be created or modified by the library
        database_uri = f'{database_path.resolve().as_uri()}?mode=ro'
        connection = None
        try:
            connection = sqlite.connect(database_uri, uri=True)
            cursor = connection.cursor()
            cursor.row_factory = sqlite.Row
            cursor.execute(f"PRAGMA key=\"x'{self.cipher_key}'\";")
            cursor.execute('PRAGMA cipher_compatibility = 3;')
            cursor.execute('SELECT * FROM Identity;').fetchone()
        except sqlite.DatabaseError:
            if connection is not None:
                connection.close()
            raise EnpassDatabaseError('Either the master password or the key file provided cannot decrypt '
                                      'the database, or it is not a valid enpass 6 encrypted database,'
                                      'or the pbkdf2_rounds is not correct. '
                                      f'The pbkdf2_rounds currently set is {self.pbkdf2_rounds}') from None
        return connection, cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        """Closes the connection to the database.

        Entries already retrieved remain usable after the database is closed.

        """
        self._connection.close()

    def _query(self, query, parameters=()):
        self._cursor.execute(query, parameters)
        # If you deleted an item from Enpass, it stays in the database, but the
        # entries are cleared so only entries with nonce are valid entries
        return [row for row in self._cursor if row["key"][32:]]

    def _get_field_rows(self, rows):
        """Retrieves the fields of the items of the rows provided grouped by item uuid.

        Args:
            rows (list): The item rows to retrieve the fields for.

        Returns:
            field_rows (dict): The field rows of each item keyed by the item uuid.

        """
        uuids = [row['uuid'] for row in rows]
        field_rows = {}
        # Chunked to stay well below the sqlite limit of bound parameters per query
        chunk_size = 500
        for index in range(0, len(uuids), chunk_size):
            chunk = uuids[index:index + chunk_size]
            placeholders = ', '.join('?' * len(chunk))
            self._cursor.execute('SELECT item_uuid, label, type, value, sensitive '
                                 'FROM itemfield '
                                 f'WHERE deleted = 0 AND item_uuid IN ({placeholders});', chunk)
            for field_row in self._cursor:
                field_rows.setdefault(field_row['item_uuid'], []).append(field_row)
        return field_rows

    def _get_entries(self, query, parameters=()):
        rows = self._query(query, parameters)
        field_rows = self._get_field_rows(rows)
        return [Entry(row, field_rows.get(row['uuid'])) for row in rows]

    @property
    def entries(self):
        """All the entries in the database.

        Returns:
            entries (list): The password entries in the database.

        """
        return self._get_entries(f'{self._retrieve_all_query};')

    def get_entry(self, name):
        """Retrieves a single entry matching the name.

        Args:
            name: The name of the password entry to retrieve.

        Returns:
            entry (Entry): A password entry object if match found else None.

        """
        query = f'{self._retrieve_all_query} WHERE lower(i.title) = ?;'
        return next((entry for entry in self._get_entries(query, (name.lower(),))),
                    None)

    def search_entries(self, name):
        """Retrieves any entry that matches the name provided (fuzzy matching).

        Args:
            name: The name to search the password entries for.

        Returns:
            entries (list): A list of password entries matching the fuzzy search for the given name.

        """
        # Escape the like wildcards so the name is matched literally
        pattern = name.lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        query = f"{self._retrieve_all_query} WHERE lower(i.title) LIKE ? ESCAPE '\\';"
        return self._get_entries(query, (f'%{pattern}%',))


class Entry:
    """Models a password entry and exposes some useful attributes about it."""

    def __init__(self, database_row, field_rows=None):
        # The key object is saved in binary from and actually consists of the
        # AES key (32 bytes) and a nonce (12 bytes) for GCM
        self.key = database_row["key"][:32]
        self.nonce = database_row["key"][32:]
        self.title = database_row["title"]
        self._password_value = database_row["password_value"]
        self._password_hash = database_row["password_value_hash"]
        self.uuid = database_row["uuid"]
        self._totp_hash = database_row["totp_value_hash"]
        self._totp_value = database_row["totp_value"]
        self._totp_sensitive = bool(database_row["totp_value_sensitive"])
        self._totp = None
        self.header = self.uuid.replace("-", "")
        self._password = None
        self.fields = [Field(self, field_row) for field_row in field_rows or []]

    @property
    def field_labels(self):
        """The labels of the fields of the entry.

        Returns:
            field_labels (list): The labels of all the fields of the entry.

        """
        return [field.label for field in self.fields]

    def _match_fields(self, name):
        name = name.lower()
        by_label = [field for field in self.fields if (field.label or '').lower() == name]
        return by_label or [field for field in self.fields if (field.type or '').lower() == name]

    def get_field(self, name):
        """Retrieves the value of a field of the entry by its label or type.

        Fields are matched case insensitively on their label first and on their type if no label matches.

        Args:
            name: The label or type of the field to retrieve.

        Returns:
            value (str): The plaintext value of the first matching field if match found else None.

        """
        return next((field.value for field in self._match_fields(name)), None)

    def get_fields(self, name):
        """Retrieves the values of all the fields of the entry matching a label or type.

        Fields are matched case insensitively on their label first and on their type if no label matches.

        Args:
            name: The label or type of the fields to retrieve.

        Returns:
            values (list): The plaintext values of all the matching fields.

        """
        return [field.value for field in self._match_fields(name)]

    @property
    def password(self):
        """The plaintext password of the entry.

        Returns:
            password (text): The plaintext password of the entry.

        """
        if self._password is None:
            if self._password_value is None:
                LOGGER.warning(f'Entry with title :{self.title} and '
                               f'uuid :{self.uuid} does not seem to have a password.')
                return None
            self._password = self._decrypt(self._password_value)
        return self._password

    def _decrypt(self, value):
        """Decrypts a value encrypted with the key of the entry.

        Args:
            value (str): The hex encoded ciphertext followed by the authentication tag.

        Returns:
            plaintext (str): The decrypted value, None if no value is provided.

        Raises:
            EnpassDecryptionError: If the value fails authentication against its tag.

        """
        if value is None:
            return None
        # The value object holds the ciphertext (same length as plaintext) +
        # (authentication) tag (16 bytes) and is stored in hex
        try:
            ciphertext = bytes.fromhex(value[:-32])
            tag = bytes.fromhex(value[-32:])
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
            cipher.update(bytes.fromhex(self.header))
            # Decrypting and verifying the tag together rejects any value that has been tampered with
            return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
        except ValueError:
            raise EnpassDecryptionError(f'Value of entry with uuid :{self.uuid} failed authentication.') from None

    @property
    def totp_seed(self):
        """The plaintext totp seed of the entry.

        Returns:
            totp_seed (text): The plaintext totp seed of the entry, decrypted if the field is sensitive.

        """
        if self._totp is None:
            self._totp = self._decrypt(self._totp_value) if self._totp_sensitive else self._totp_value
        return self._totp


class Field:
    """Models a field of a password entry and exposes its plaintext value."""

    def __init__(self, entry, field_row):
        self._entry = entry
        self.label = field_row["label"]
        self.type = field_row["type"]
        self.sensitive = bool(field_row["sensitive"])
        self._raw_value = field_row["value"]
        self._value = None

    @property
    def value(self):
        """The plaintext value of the field.

        Returns:
            value (text): The plaintext value of the field, decrypted if the field is sensitive.

        """
        if self._value is None:
            self._value = self._entry._decrypt(self._raw_value) if self.sensitive else self._raw_value  # noqa
        return self._value
