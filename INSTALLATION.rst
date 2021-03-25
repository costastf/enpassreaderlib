============
Installation
============

At the command line::

    $ pip install enpassreaderlib

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv enpassreaderlib
    $ pip install enpassreaderlib

Or, if you are using pipenv::

    $ pipenv install enpassreaderlib

Or, if you are using pipx::

    $ pipx install enpassreaderlib

Important note for pysqlcipher3:

pysqlcipher3 needs to compile on your workstation and it might not succeed if header files are missing.
On my Mac I had to follow something like the below process::

    brew install sqlcipher
    # Assuming the version installed is 4.4.3 adjust accordingly
    export C_INCLUDE_PATH=$BREWPATH/Cellar/sqlcipher/4.4.3/include
    export LIBRARY_PATH=$BREWPATH/Cellar/sqlcipher/4.4.3/lib
    # Activate the virtual environment that the project is installed to fix the installation
    . .venv/bin/activate
    pip install pysqlcipher3

On linux based systems probably sqlcipher-dev will need to be installed for the package to succesfully compile.

