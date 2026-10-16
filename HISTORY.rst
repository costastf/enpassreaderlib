.. :changelog:

History
-------

0.0.1 (25-03-2021)
---------------------

* First code creation


0.1.0 (25-03-2021)
------------------

* First release with basic required functionality.


0.1.1 (25-03-2021)
------------------

* Loosely pinned dependencies and updated the usage and installation notes a bit.


0.1.2 (07-07-2021)
------------------

* Added pipeline.


0.2.0 (02-03-2023)
------------------

* Expose totp seeds for passwords that support it.


0.2.1 (02-03-2023)
------------------

* Fix linting.


0.2.2 (02-03-2023)
------------------

* Fix for entries with no password.


0.2.3 (10-08-2023)
------------------

* Update to latest default configured pbkdf2 rounds.


0.2.4 (10-08-2023)
------------------

* Fix pipeline with required dependencies for upload.


0.2.5 (10-08-2023)
------------------

* Remove debugging logging.


0.3.0 (16-10-2026)
------------------

* Exposed more fields of an entry. Bumped minimum python version and dependencies.


0.4.0 (16-10-2026)
------------------

* Fix for sql injection.


0.4.1 (16-10-2026)
------------------

* Verify the gcm authentication tag when decrypting values, tampered values raise EnpassDecryptionError.
* Open the database read only and stop creating an empty file for a missing path.
* Close the database connection, with close and context manager support.
* Quote field types as sql string literals in the entries query.
* Leave entry titles out of the missing password warning.
* Parse key files by their key element, invalid key files raise EnpassKeyfileError.
* Skip items without a key when listing entries.
