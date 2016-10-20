% GOCRYPTFS(1)
% github.com/rfjakob
% Oct 2016

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

gocryptfs [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]

Change password
---------------

gocryptfs -passwd [OPTIONS] CIPHERDIR

DESCRIPTION
===========

Options:

**-aessiv**
:	Use the AES-SIV encryption mode. This is slower than GCM but is
	secure with deterministic nonces as used in "-reverse" mode.

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
:	Stay in the foreground instead of forking away. Implies "-nosyslog".

**-fusedebug**
:	Enable fuse library debug output

**-init**
:	Initialize encrypted directory

**-ko**
:	Pass additonal mount options to the kernel (comma-separated list).
	FUSE filesystems are mounted with "nodev,nosuid" by default. If gocryptfs
	runs as root, you can enable device files by passing the opposite mount option,
	"dev", and if you want to enable suid-binaries, pass "suid".
	"ro" (equivalent to passing the "-ro" option) and "noexec" may also be
	interesting. For a complete list see the section
	`FILESYSTEM-INDEPENDENT MOUNT OPTIONS` in mount(8).

**-longnames**
:	Store names longer than 176 bytes in extra files (default true)
	This flag is useful when recovering old gocryptfs filesystems using
	"-masterkey". It is ignored (stays at the default) otherwise.

**-masterkey string**
:	Use a explicit master key specified on the command line. This
	option can be used to mount a gocryptfs filesystem without a config file.
	Note that the command line, and with it the master key, is visible to
	anybody on the machine who can execute "ps -auxwww".
	This is meant as a recovery option for emergencies, such as if you have
	forgotten your password.
	
	Example master key:  
	6f717d8b-6b5f8e8a-fd0aa206-778ec093-62c5669b-abd229cd-241e00cd-b4d6713d

**-memprofile string**
:	Write memory profile to the specified file. This is useful when debugging
	memory usage of gocryptfs.

**-nonempty**
:	Allow mounting over non-empty directories. FUSE by default disallows
	this to prevent accidential shadowing of files.

**-nosyslog**
:	Diagnostic messages are normally redirected to syslog once gocryptfs
	daemonizes. This option disables the redirection and messages will
	continue be printed to stdout and stderr.

**-notifypid int**
:	Send USR1 to the specified process after successful mount. This is
	used internally for daemonization.

**-openssl bool/"auto"**
:	Use OpenSSL instead of built-in Go crypto (default "auto"). Using
	built-in crypto is 4x slower unless your CPU has AES instructions and
	you are using Go 1.6+. In mode "auto", gocrypts chooses the faster
	option.

**-passfile string**
:	Read password from the specified file. This is a shortcut for
	specifying "-extpass /bin/cat FILE".

**-passwd**
:	Change the password. Will ask for the old password, check if it is
	correct, and ask for a new one.
	
	This can be used together with `-masterkey` if
	you forgot the password but know the master key. Note that without the
	old password, gocryptfs cannot tell if the master key is correct and will
	overwrite the old one without mercy. It will, however, create a backup copy
	of the old config file as `gocryptfs.conf.bak`. Delete it after
	you have verified that you can access your files with the
	new password.

**-plaintextnames**
:	Do not encrypt file names and symlink targets

**-q, -quiet**
:	Quiet - silence informational messages

**-reverse**
:	Reverse mode shows a read-only encrypted view of a plaintext
	directory. Implies "-aessiv".

**-ro**
:	Mount the filesystem read-only

**-scryptn int**
:	scrypt cost parameter logN. Setting this to a lower value speeds up
	mounting but makes the password susceptible to brute-force attacks
	(default 16)

**-version**
:	Print version and exit. The output contains three fields seperated by ";".
	Example: "gocryptfs v0.12-2; go-fuse a4c968c; go1.6.2".
	Field 1 is the gocryptfs version, field 2 is the version of the go-fuse
	library, field 3 is the Go version that was used to compile the binary.

**-wpanic**
:	When encountering a warning, panic and exit immediately. This is
	useful in regression testing.

**-zerokey**
:	Use all-zero dummy master key. This options is only intended for
	automated testing as it does not provide any security.


Comma-Separated-Options:

For compatibility with mount(1), options are also accepted as
"-o COMMA-SEPARATED-OPTIONS" at the end of the command line.
For example, "-o q,zerokey" is equivalent to "-q -zerokey".

EXAMPLES
========

Create and mount an encrypted filesystem:

mkdir /tmp/g1 /tmp/g2

gocryptfs -init /tmp/g1  
gocryptfs /tmp/g1 /tmp/g2


SEE ALSO
========
fuse(8)
