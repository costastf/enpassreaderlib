=====
Usage
=====


To develop on enpassreaderlib:

.. code-block:: bash

    # The following commands require pipenv as a dependency

    # To lint the project
    _CI/scripts/lint.py

    # To execute the testing
    _CI/scripts/test.py

    # To create a graph of the package and dependency tree
    _CI/scripts/graph.py

    # To build a package of the project under the directory "dist/"
    _CI/scripts/build.py

    # To see the package version
    _CI/scripts/tag.py

    # To bump semantic versioning [--major|--minor|--patch]
    _CI/scripts/tag.py --major|--minor|--patch

    # To upload the project to a pypi repo if user and password are properly provided
    _CI/scripts/upload.py

    # To build the documentation of the project
    _CI/scripts/document.py


To use enpassreaderlib in a project:

.. code-block:: python

    from enpassreaderlib import EnpassDB
    enpass = EnpassDB('db_file_path', 'db_master_password', 'optional_key_file')

    # Get a specific entry
    entry = enpass.get_entry('ENTRY_TITLE')
    entry.password

    # Search with fuzzy searching
    for entry in enpass.search_entries('SOME_PART_OF_A_PASSWORD_TITLE'):
        print(f'{entry.title}  {entry.password}')

    # Iterate over all the entries of the database
    for entry in enpass.entries:
        print(f'{entry.title}  {entry.password}')
