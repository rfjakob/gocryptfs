Stable CLI ABI
==============

If you want to call gocryptfs from your script or app, this is the
stable ABI.

General
-------

1. A password is piped into gocryptfs with an optional terminating
   newline. Any unexpected data after the final newline will
   cause gocryptfs to abort.
2. Always pass "--" after the options. This prevents a CIPERDIR that
   starts with a dash ("-") to wreak havoc.
3. Use "-q" to get rid of all informational messages. Only error
   messages (if any) will be printed to stderr (capture it!).
4. Check the exit code of gocryptfs. 0 is success, anything else is an
   error and details about that error will have been printed to stderr.

Initialize Filesystem
---------------------

#### Bash example

    $ cat mypassword.txt | gocryptfs -init -q -- CIPHERDIR

Content of "mypassword.txt":

    mypassword1234

#### What you have to pipe to gocryptfs

1. Password
2. Optional newline

#### Notes

1. The CIPHERDIR directory must exist and be empty

#### Exit Codes

* 0 = success
* 6 = CIPHERDIR is invalid: not an empty directory
* 22 = password is empty
* 24 = could not create gocryptfs.conf
* other = please inspect the message

Mount
-----

#### Bash example

    $ cat mypassword.txt | gocryptfs -q -- CIPHERDIR MOUNTPOINT

#### What you have to pipe to gocryptfs

Same as for "Initialize Filesystem".

#### Notes

1. The MOUNTPOINT directory must exist and be empty.

#### Exit Codes

* 0 = success
* 10 = MOUNTPOINT is not an empty directory or contains CIPHERDIR
* 12 = password incorrect
* 23 = gocryptfs.conf could not be opened (does not exist, is unreadable, ...)
* other = please inspect the message

Change Password
---------------

#### Bash example

    $ cat change.txt | gocryptfs -passwd -q -- CIPHERDIR

Content of "change.txt":

    mypassword1234
    newpassword9876

#### What you have to pipe to gocryptfs

1. Old password
2. Newline
3. New password
4. Optional newline

#### Exit Codes

* 0 = success
* 12 = password incorrect
* 23 = gocryptfs.conf could not be opened for reading
* 24 = could not write the updated gocryptfs.conf
* other = please inspect the message

Further Reading
---------------

Additional exit codes that are unlikely to occur are defined in
[exitcodes.go](../internal/exitcodes/exitcodes.go).
