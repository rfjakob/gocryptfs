% GOCRYPTFS(1)
% github.com/rfjakob
% Oct 2016

NAME
====

gocryptfs - mount an encrypted directory

SYNOPSIS
========

#### Initialize encrypted filesystem
gocryptfs -init [OPTIONS] CIPHERDIR

#### Mount
gocryptfs [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]

#### Change password
gocryptfs -passwd [OPTIONS] CIPHERDIR

DESCRIPTION
===========

Available options are listed below.

#### -aessiv
Use the AES-SIV encryption mode. This is slower than GCM but is
secure with deterministic nonces as used in "-reverse" mode.

#### -allow_other
By default, the Linux kernel prevents any other user (even root) to
access a mounted FUSE filesystem. Settings this option allows access for
other users, subject to file permission checking. Only works if
user_allow_other is set in /etc/fuse.conf. This option is equivalent to
"allow_other" plus "default_permissions" described in fuse(8).

#### -config string
Use specified config file instead of CIPHERDIR/gocryptfs.conf

#### -cpuprofile string
Write cpu profile to specified file

#### -ctlsock string
Create a control socket at the specified location. The socket can be
used to decrypt and encrypt paths inside the filesystem. When using
this option, make sure that the direcory you place the socket in is
not world-accessible. For example, `/run/user/UID/my.socket` would 
be suitable.

#### -d, -debug
Enable debug output

#### -extpass string
Use an external program (like ssh-askpass) for the password prompt.
The program should return the password on stdout, a trailing newline is
stripped by gocryptfs. Using something like "cat /mypassword.txt" allows
to mount the gocryptfs filesytem without user interaction.

#### -fg, -f
Stay in the foreground instead of forking away. Implies "-nosyslog".
For compatability, "-f" is also accepted, but "-fg" is preferred.

#### -force_owner string
If given a string of the form "uid:gid" (where both "uid" and "gid" are
substituted with positive integers), presents all files as owned by the given
uid and gid, regardless of their actual ownership. Implies "allow_other".

This is rarely desired behavior: One should *usually* run gocryptfs as the
account which owns the backing-store files, which should *usually* be one and
the same with the account intended to access the decrypted content. An example
of a case where this may be useful is a situation where content is stored on a
filesystem that doesn't properly support UNIX ownership and permissions.

#### -forcedecode
Force decode of encrypted files even if the integrity check fails, instead of
failing with an IO error. Warning messages are still printed to syslog if corrupted 
files are encountered.
It can be useful to recover files from disks with bad sectors or other corrupted
media. It shall not be used if the origin of corruption is unknown, specially
if you want to run executable files.

For corrupted media, note that you probably want to use dd_rescue(1)
instead, which will recover all but the corrupted 4kB block.

This option makes no sense in reverse mode. It requires gocryptfs to be compiled with openssl
support and implies -openssl true. Because of this, it is not compatible with -aessiv,
that uses built-in Go crypto.

Setting this option forces the filesystem to read-only and noexec.

#### -fsname string
Override the filesystem name (first column in df -T). Can also be
passed as "-o fsname=" and is equivalent to libfuse's option of the
same name. By default, CIPHERDIR is used.

#### -fusedebug
Enable fuse library debug output

#### -h, -help
Print a short help text that shows the more-often used options.

#### -hh
Long help text, shows all available options.

#### -hkdf
Use HKDF to derive separate keys for content and name encryption from
the master key.

#### -info
Pretty-print the contents of the config file for human consumption,
stripping out sensitive data.

#### -init
Initialize encrypted directory

#### -ko
Pass additonal mount options to the kernel (comma-separated list).
FUSE filesystems are mounted with "nodev,nosuid" by default. If gocryptfs
runs as root, you can enable device files by passing the opposite mount option,
"dev", and if you want to enable suid-binaries, pass "suid".
"ro" (equivalent to passing the "-ro" option) and "noexec" may also be
interesting. For a complete list see the section
`FILESYSTEM-INDEPENDENT MOUNT OPTIONS` in mount(8).

#### -longnames
Store names longer than 176 bytes in extra files (default true)
This flag is useful when recovering old gocryptfs filesystems using
"-masterkey". It is ignored (stays at the default) otherwise.

#### -masterkey string
Use a explicit master key specified on the command line. This
option can be used to mount a gocryptfs filesystem without a config file.
Note that the command line, and with it the master key, is visible to
anybody on the machine who can execute "ps -auxwww".
This is meant as a recovery option for emergencies, such as if you have
forgotten your password.

Example master key:  
6f717d8b-6b5f8e8a-fd0aa206-778ec093-62c5669b-abd229cd-241e00cd-b4d6713d

#### -memprofile string
Write memory profile to the specified file. This is useful when debugging
memory usage of gocryptfs.

#### -nonempty
Allow mounting over non-empty directories. FUSE by default disallows
this to prevent accidential shadowing of files.

#### -noprealloc
Disable preallocation before writing. By default, gocryptfs
preallocates the space the next write will take using fallocate(2)
in mode FALLOC_FL_KEEP_SIZE. The preallocation makes sure it cannot
run out of space in the middle of the write, which would cause the
last 4kB block to be corrupt and unreadable.

On ext4, preallocation is fast and does not cause a
noticeable performance hit. Unfortunately, on Btrfs, preallocation
is very slow, especially on rotational HDDs. The "-noprealloc"
option gives users the choice to trade robustness against
out-of-space errors for a massive speedup.

For benchmarks and more details of the issue see
https://github.com/rfjakob/gocryptfs/issues/63 .

#### -nosyslog
Diagnostic messages are normally redirected to syslog once gocryptfs
daemonizes. This option disables the redirection and messages will
continue be printed to stdout and stderr.

#### -notifypid int
Send USR1 to the specified process after successful mount. This is
used internally for daemonization.

#### -o COMMA-SEPARATED-OPTIONS
For compatibility with mount(1), options are also accepted as
"-o COMMA-SEPARATED-OPTIONS" at the end of the command line.
For example, "-o q,zerokey" is equivalent to passing "-q -zerokey".

#### -openssl bool/"auto"
Use OpenSSL instead of built-in Go crypto (default "auto"). Using
built-in crypto is 4x slower unless your CPU has AES instructions and
you are using Go 1.6+. In mode "auto", gocrypts chooses the faster
option.

#### -passfile string
Read password from the specified file. This is a shortcut for
specifying '-extpass="/bin/cat -- FILE"'.

#### -passwd
Change the password. Will ask for the old password, check if it is
correct, and ask for a new one.

This can be used together with `-masterkey` if
you forgot the password but know the master key. Note that without the
old password, gocryptfs cannot tell if the master key is correct and will
overwrite the old one without mercy. It will, however, create a backup copy
of the old config file as `gocryptfs.conf.bak`. Delete it after
you have verified that you can access your files with the
new password.

#### -plaintextnames
Do not encrypt file names and symlink targets

#### -q, -quiet
Quiet - silence informational messages

#### -raw64
Use unpadded base64 encoding for file names. This gets rid of the
trailing "\\=\\=". A filesystem created with this option can only be
mounted using gocryptfs v1.2 and higher.

#### -reverse
Reverse mode shows a read-only encrypted view of a plaintext
directory. Implies "-aessiv".

#### -ro
Mount the filesystem read-only

#### -scryptn int
scrypt cost parameter expressed as scryptn=log2(N). Possible values are
10 to 28, representing N=2^10 to N=2^28.

Setting this to a lower
value speeds up mounting and reduces its memory needs, but makes
the password susceptible to brute-force attacks. The default is 16.

#### -serialize_reads
The kernel usually submits multiple concurrent reads to service
userspace requests and kernel readahead. gocryptfs serves them
concurrently and in arbitrary order. On backing storage that performs
poorly for concurrent or out-of-order reads (like Amazon Cloud Drive),
this behavoir can cause very slow read speeds.

The `-serialize_reads`
option does two things: (1) reads will be submitted one-by-one (no
concurrency) and (2) gocryptfs tries to order the reads by file
offset order.

The ordering requires gocryptfs to wait a certain time before
submitting a read. The serialization introduces extra locking.
These factors will limit throughput to below 70MB/s.

For more details visit https://github.com/rfjakob/gocryptfs/issues/92 .

#### -speed
Run crypto speed test. Benchmark Go's built-in GCM against OpenSSL
(if available). The library that will be selected on "-openssl=auto"
(the default) is marked as such.

#### -trace string
Write execution trace to file. View the trace using "go tool trace FILE".

#### -version
Print version and exit. The output contains three fields seperated by ";".
Example: "gocryptfs v1.1.1-5-g75b776c; go-fuse 6b801d3; 2016-11-01 go1.7.3".
Field 1 is the gocryptfs version, field 2 is the version of the go-fuse
library, field 3 is the compile date and the Go version that was
used.

#### -wpanic
When encountering a warning, panic and exit immediately. This is
useful in regression testing.

#### -zerokey
Use all-zero dummy master key. This options is only intended for
automated testing as it does not provide any security.

#### --
Stop option parsing. Helpful when CIPHERDIR may start with a
dash "-".

EXAMPLES
========

Create an encrypted filesystem in directory "g1" and mount it on "g2":

	mkdir g1 g2
	gocryptfs -init g1
	gocryptfs g1 g2

Mount an ecrypted view of joe's home directory using reverse mode:

	mkdir /home/joe.crypt
	gocryptfs -init -reverse /home/joe
	gocryptfs -reverse /home/joe /home/joe.crypt

EXIT CODES
==========

0: success  
12: password incorrect  
other: please check the error message

SEE ALSO
========
fuse(8) fallocate(2)
