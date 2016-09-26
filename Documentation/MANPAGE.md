% GOCRYPTFS(1)
% github.com/rfjakob
% May 2016

NAME
====

gocryptfs - mount an encrypted directory

SYNOPSIS
========

Initialize encrypted filesystem
-------------------------------

gocryptfs -init [OPTIONS] CIPHERDIR

Mount
-----

gocryptfs [OPTIONS] CIPHERDIR MOUNTPOINT

Change password
---------------

gocryptfs -passwd [OPTIONS] CIPHERDIR

DESCRIPTION
===========

Options:

**-aessiv**
:	Use the AES-SIV encryption mode (implied by -reverse)

**-allow_other**
:	By default, the Linux kernel prevents any other user (even root) to
access a mounted FUSE filesystem. Settings this option allows access for
other users, subject to file permission checking. Only works if
user_allow_other is set in /etc/fuse.conf. This option is equivalent to
"allow_other" plus "default_permissions" described in fuse(8).

**-config string**
:	Use specified config file instead of CIPHERDIR/gocryptfs.conf

**-cpuprofile string**
:	Write cpu profile to specified file

**-d, -debug**
:	Enable debug output

**-extpass string**
:	Use an external program (like ssh-askpass) for the password prompt.
The program should return the password on stdout, a trailing newline is
stripped by gocryptfs. Using something like "cat /mypassword.txt" allows
to mount the gocryptfs filesytem without user interaction.

**-f**
:	Stay in the foreground instead of forking away.

**-fusedebug**
:	Enable fuse library debug output

**-init**
:	Initialize encrypted directory

**-longnames**
:	Store names longer than 176 bytes in extra files (default true)
This flag is useful when recovering old gocryptfs filesystems using
"-masterkey". It is ignored (stays at the default) otherwise.

**-masterkey string**
:	Mount with explicit master key specified on the command line. This
option can be used to mount a gocryptfs filesystem without a config file.
Note that the command line, and with it the master key, is visible to
anybody on the machine who can execute "ps -auxwww".

**-memprofile string**
:	Write memory profile to specified file. This is useful when debugging
memory usage of gocryptfs.

**-nosyslog**
:	Diagnostic messages are normally redirected to syslog once gocryptfs
daemonizes. This option disables the redirection and messages will
continue be printed to stdout and stderr.

**-notifypid int**
:	Send USR1 to the specified process after successful mount. This is
used internally for daemonization.

**-o**
: Pass additonal mount options to the kernel (comma-separated list).
FUSE filesystems are mounted with "nodev,nosuid" by default. If gocryptfs
runs as root, you can enable device files by passing the opposite mount option,
"dev", and if you want to enable suid-binaries, pass "suid".
"ro" (equivalent to passing the "-ro" option) and "noexec" may also be
interesting. For a complete liste see the section
`FILESYSTEM-INDEPENDENT MOUNT OPTIONS` in mount(8).

**-openssl bool/"auto"**
:	Use OpenSSL instead of built-in Go crypto (default "auto"). Using
built-in crypto is 4x slower unless your CPU has AES instructions and
you are using Go 1.6+. In mode "auto", gocrypts chooses the faster
option.

**-passwd**
:	Change password

**-plaintextnames**
:	Do not encrypt file names and symlink targets

**-q, -quiet**
:	Quiet - silence informational messages

**-reverse**
:	Reverse mode shows a read-only encrypted view of a plaintext
directory

**-ro**
:	Mount the filesystem read-only

**-scryptn int**
:	scrypt cost parameter logN. Setting this to a lower value speeds up
mounting but makes the password susceptible to brute-force attacks (default 16)

**-version**
:	Print version and exit. The output contains three fields seperated by
";". Example: "gocryptfs v0.12-2; go-fuse a4c968c; go1.6.2".
Field 1 is the gocryptfs version, field 2 is the version of the go-fuse
library, field 3 is the Go version that was used to compile the binary.

**-wpanic**
:	When encountering a warning, panic and exit immediately. This is
useful in regression testing.

**-zerokey**
:	Use all-zero dummy master key. This options is only intended for
automated testing as it does not provide any security.


EXAMPLES
========

Create and mount an encrypted filesystem:

mkdir /tmp/g1 /tmp/g2

gocryptfs -init /tmp/g1  
gocryptfs /tmp/g1 /tmp/g2


SEE ALSO
========
fuse(8)
