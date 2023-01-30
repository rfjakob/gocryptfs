% GOCRYPTFS(1)
% github.com/rfjakob
% Aug 2017

NAME
====

gocryptfs - create or mount an encrypted filesystem

SYNOPSIS
========

#### Initialize new encrypted filesystem
`gocryptfs -init [OPTIONS] CIPHERDIR`

#### Mount
`gocryptfs [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]`

#### Unmount
`fusermount -u MOUNTPOINT`

#### Change password
`gocryptfs -passwd [OPTIONS] CIPHERDIR`

#### Check consistency
`gocryptfs -fsck [OPTIONS] CIPHERDIR`

#### Show filesystem information
`gocryptfs -info [OPTIONS] CIPHERDIR`

DESCRIPTION
===========

gocryptfs is an encrypted overlay filesystem written in Go.
Encrypted files are stored in CIPHERDIR, and a plain-text
view can be presented by mounting the filesystem at MOUNTPOINT.

gocryptfs was inspired by encfs(1) and strives to fix its
security issues while providing good performance.

ACTION FLAGS
============

Unless one of the following *action flags* is passed, the default
action is to mount a filesystem (see SYNOPSIS).

#### -fsck
Check CIPHERDIR for consistency. If corruption is found, the
exit code is 26.

#### -h, -help
Print a short help text that shows the more-often used options.

#### -hh
Long help text, shows all available options.

#### -info
Pretty-print the contents of the config file in CIPHERDIR for
human consumption, stripping out sensitive data.

Example:

    $ gocryptfs -info my_cipherdir
    Creator:      gocryptfs v2.0-beta2
    FeatureFlags: GCMIV128 HKDF DirIV EMENames LongNames Raw64
    EncryptedKey: 64B
    ScryptObject: Salt=32B N=65536 R=8 P=1 KeyLen=32

#### -init
Initialize encrypted directory.

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

#### -speed
Run crypto speed test. Benchmark Go's built-in GCM against OpenSSL
(if available). The library that will be selected on "-openssl=auto"
(the default) is marked as such.

#### -version
Print version and exit. The output contains three fields separated by ";".
Example: "gocryptfs v1.1.1-5-g75b776c; go-fuse 6b801d3; 2016-11-01 go1.7.3".
Field 1 is the gocryptfs version, field 2 is the version of the go-fuse
library, field 3 is the compile date and the Go version that was
used.

INIT OPTIONS
============

Available options for `-init` are listed below. Usually, you don't need any.
Defaults are fine.

#### -aessiv
Use the AES-SIV encryption mode. This is slower than AES-GCM but is
secure with deterministic nonces as used in "-reverse" mode.

Run `gocryptfs -speed` to find out if and how much slower.

#### -deterministic-names
Disable file name randomisation and creation of `gocryptfs.diriv` files.
This can prevent sync conflicts conflicts when synchronising files, but
leaks information about identical file names across directories
("Identical names leak" in https://nuetzlich.net/gocryptfs/comparison/#file-names ).

The resulting `gocryptfs.conf` has "DirIV" missing from "FeatureFlags".

#### -devrandom
Obsolete and ignored on gocryptfs v2.2 and later.

See https://github.com/rfjakob/gocryptfs/commit/f3c777d5eaa682d878c638192311e52f9c204294
and https://github.com/rfjakob/gocryptfs/issues/596 for background info.

#### -hkdf
Use HKDF to derive separate keys for content and name encryption from
the master key. Default true.

#### -longnamemax

    integer value, allowed range 62...255

Hash file names that (in encrypted form) exceed this length. The default
is 255, which aligns with the usual name length limit on Linux and
provides best performance.

However, online storage may impose lower limits on file name and/or
path length. In this case, setting -longnamemax to a lower value
can be helpful.

The lower the value, the more extra `.name` files
must be created, which slows down directory listings.

Values below 62 are not allowed as then the hashed name
would be longer than the original name.

Example:

    -longnamemax 100

#### -plaintextnames
Do not encrypt file names and symlink targets.

#### -raw64
Use unpadded base64 encoding for file names. This gets rid of the
trailing "\\=\\=". A filesystem created with this option can only be
mounted using gocryptfs v1.2 and higher. Default true.

#### -reverse
Reverse mode shows a read-only encrypted view of a plaintext
directory. Implies "-aessiv".

#### -xchacha
Use XChaCha20-Poly1305 file content encryption. This should be much faster
than AES-GCM on CPUs that lack AES acceleration.

Run `gocryptfs -speed` to find out if and how much faster.

MOUNT OPTIONS
=============

Available options for mounting are listed below. Usually, you don't need any.
Defaults are fine.

#### -acl
Enable ACL enforcement. When you want to use ACLs, you must enable this
option.

#### -allow_other
By default, the Linux kernel prevents any other user (even root) to
access a mounted FUSE filesystem. Settings this option allows access for
other users, subject to file permission checking. Only works if
user_allow_other is set in /etc/fuse.conf. This option is equivalent to
"allow_other" plus "default_permissions" described in fuse(8).

#### -badname string
When gocryptfs encounters a "bad" file name (cannot be decrypted or decrypts
to garbage), a warning is logged and the file is hidden from the
plaintext view.

With the `-badname` option, you can select "bad" file names that should
still be shown in the plaintext view instead of hiding them. Bad files
will get ` GOCRYPTFS_BAD_NAME` appended to their name.

Glob pattern. Can be passed multiple times for multiple patterns.

Examples:

Dropbox sync conflicts:

    -badname '*conflicted copy*'

Syncthing sync conflicts:

    -badname '*.sync-conflict*'

Show all invalid filenames:

    -badname '*'

#### -ctlsock string
Create a control socket at the specified location. The socket can be
used to decrypt and encrypt paths inside the filesystem. When using
this option, make sure that the directory you place the socket in is
not world-accessible. For example, `/run/user/UID/my.socket` would
be suitable.

#### -dev, -nodev
Enable (`-dev`) or disable (`-nodev`) device files in a gocryptfs mount
(default: `-nodev`). If both are specified, `-nodev` takes precedence.
You need root permissions to use `-dev`.

#### -e PATH, -exclude PATH
Only for reverse mode: exclude relative plaintext path from the encrypted
view, matching only from root of mounted filesystem. Can be passed multiple
times.

Example that excludes the directories "Music" and "Movies" from the root
directory:

    gocryptfs -reverse -exclude Music -exclude Movies /home/user /mnt/user.encrypted

See also `-exclude-wildcard`, `-exclude-from` and the [EXCLUDING FILES](#excluding-files) section.

#### -ew GITIGNORE-PATTERN, -exclude-wildcard GITIGNORE-PATTERN
Only for reverse mode: exclude paths from the encrypted view in gitignore(5) syntax,
wildcards supported. Pass multiple times for multiple patterns.

Example to exclude all `.mp3` files in any directory:

    gocryptfs -reverse -exclude-wildcard '*.mp3' /home/user /mnt/user.encrypted

Example to to exclude everything but the directory 'important' in the root dir:

    gocryptfs -reverse -exclude-wildcard '*' -exclude-wildcard '!/important' /home/user /mnt/user.encrypted

See also `-exclude-from` and the [EXCLUDING FILES](#excluding-files) section.

#### -exclude-from FILE
Only for reverse mode: reads gitignore patterns
from a file. Can be passed multiple times. Example:

    gocryptfs -reverse -exclude-from ~/crypt-exclusions /home/user /mnt/user.encrypted

See also `-exclude`, `-exclude-wildcard` and the [EXCLUDING FILES](#excluding-files) section.

#### -exec, -noexec
Enable (`-exec`) or disable (`-noexec`) executables in a gocryptfs mount
(default: `-exec`). If both are specified, `-noexec` takes precedence.

#### -fg, -f
Stay in the foreground instead of forking away.
For compatibility, "-f" is also accepted, but "-fg" is preferred.

Unless `-notifypid` is also passed, the logs go to stdout and stderr
instead of syslog.

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
Obsolete and ignored on gocryptfs v2.2 and later.

See https://github.com/rfjakob/gocryptfs/commit/d023cd6c95fcbc6b5056ba1f425d2ac3df4abc5a
for what it was and why it was dropped.

#### -fsname string
Override the filesystem name (first column in df -T). Can also be
passed as "-o fsname=" and is equivalent to libfuse's option of the
same name. By default, CIPHERDIR is used.

#### -fusedebug
Enable fuse library debug output.

#### -i duration, -idle duration
Only for forward mode: automatically unmount the filesystem if it has been idle
for the specified duration. Durations can be specified like "500s" or "2h45m".
0 (the default) means stay mounted indefinitely.

When a process has open files or its working directory in the mount,
this will keep it not idle indefinitely.

#### -kernel_cache
Enable the kernel_cache option of the FUSE filesystem, see fuse(8) for details.

#### -ko
Pass additional mount options to the kernel (comma-separated list).
FUSE filesystems are mounted with "nodev,nosuid" by default. If gocryptfs
runs as root, you can enable device files by passing the opposite mount option,
"dev", and if you want to enable suid-binaries, pass "suid".
"ro" (equivalent to passing the "-ro" option) and "noexec" may also be
interesting. For a complete list see the section
`FILESYSTEM-INDEPENDENT MOUNT OPTIONS` in mount(8). On MacOS, "local" enables volume-based trash
if you have `.Trashes` folder in the root of your volume (might need to be manually created)
note, though, that "local" is marked as "experimental" in [osxfuse](https://github.com/osxfuse/osxfuse/wiki/Mount-options#local);
"noapplexattr", "noappledouble" may also be interesting.

Note that unlike "-o", "-ko" is a regular option and must be passed BEFORE
the directories. Example:

    gocryptfs -ko noexec /tmp/foo /tmp/bar

#### -longnames
Store names that are longer than 175 bytes in extra files (default true).

This flag is only useful when recovering very old gocryptfs filesystems (gocryptfs v0.8 and earlier)
using "-masterkey". It is ignored (stays at the default) otherwise.

#### -nodev
See `-dev, -nodev`.

#### -noexec
See `-exec, -noexec`.

#### -nofail
Having the `nofail` option in `/etc/fstab` instructs `systemd` to continue
booting normally even if the mount fails (see `man systemd.fstab`).

The option is ignored by `gocryptfs` itself and has no effect outside `/etc/fstab`.

#### -nonempty
Allow mounting over non-empty directories. FUSE by default disallows
this to prevent accidental shadowing of files.

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

#### -nosuid
See `-suid, -nosuid`.

#### -nosyslog
Diagnostic messages are normally redirected to syslog once gocryptfs
daemonizes. This option disables the redirection and messages will
continue be printed to stdout and stderr.

#### -notifypid int
Send USR1 to the specified process after successful mount. This is
used internally for daemonization.

#### -one-file-system
Don't cross filesystem boundaries (like rsync's `--one-file-system`).
Mountpoints will appear as empty directories.

Only applicable to reverse mode.

Limitation: Mounted single files (yes this is possible) are NOT hidden.

#### -rw, -ro
Mount the filesystem read-write (`-rw`, default) or read-only (`-ro`).
If both are specified, `-ro` takes precedence.

#### -reverse
See the `-reverse` section in INIT FLAGS. You need to specify the
`-reverse` option both at `-init` and at mount.

#### -serialize_reads
The kernel usually submits multiple concurrent reads to service
userspace requests and kernel readahead. gocryptfs serves them
concurrently and in arbitrary order. On backing storage that performs
poorly for concurrent or out-of-order reads (like Amazon Cloud Drive),
this behavior can cause very slow read speeds.

The `-serialize_reads`
option does two things: (1) reads will be submitted one-by-one (no
concurrency) and (2) gocryptfs tries to order the reads by file
offset order.

The ordering requires gocryptfs to wait a certain time before
submitting a read. The serialization introduces extra locking.
These factors will limit throughput to below 70MB/s.

For more details visit https://github.com/rfjakob/gocryptfs/issues/92 .

#### -sharedstorage
Enable work-arounds so gocryptfs works better when the backing
storage directory is concurrently accessed by multiple gocryptfs
instances.

At the moment, it does two things:

1. Disable stat() caching so changes to the backing storage show up
   immediately.
2. Disable hard link tracking, as the inode numbers on the backing
   storage are not stable when files are deleted and re-created behind
   our back. This would otherwise produce strange "file does not exist"
   and other errors.

When "-sharedstorage" is active, performance is reduced and hard
links cannot be created.

Even with this flag set, you may hit occasional problems. Running
gocryptfs on shared storage does not receive as much testing as the
usual (exclusive) use-case. Please test your workload in advance
and report any problems you may hit.

More info: https://github.com/rfjakob/gocryptfs/issues/156

#### -suid, -nosuid
Enable (`-suid`) or disable (`-nosuid`) suid and sgid executables in a gocryptfs
mount (default: `-nosuid`). If both are specified, `-nosuid` takes precedence.
You need root permissions to use `-suid`.

#### -zerokey
Use all-zero dummy master key. This options is only intended for
automated testing as it does not provide any security.

COMMON OPTIONS
==============

Options that apply to more than one action are listed below.
Each options lists where it is applicable. Again, usually you
don't need any.

#### -config string
Use specified config file instead of `CIPHERDIR/gocryptfs.conf`.

Applies to: all actions that use a config file: mount, `-fsck`, `-passwd`, `-info`, `-init`.

#### -cpuprofile string
Write cpu profile to specified file.

Applies to: all actions.

#### -d, -debug
Enable debug output.

Applies to: all actions.

#### -extpass CMD [-extpass ARG1 ...]
Use an external program (like ssh-askpass) for the password prompt.
The program should return the password on stdout, a trailing newline is
stripped by gocryptfs. If you just want to read from a password file, see `-passfile`.

When `-extpass` is specified once, the string argument will be split on spaces.
For example, `-extpass "md5sum my password.txt"` will be executed as
`"md5sum" "my" "password.txt"`, which is NOT what you want.

Specify `-extpass` twice or more to use the string arguments as-is.
For example, you DO want to call `md5sum` like this:
`-extpass "md5sum" -extpass "my password.txt"`.

If you want to prevent splitting on spaces but don't want to pass arguments
to your program, use `"--"`, which is accepted by most programs:
`-extpass "my program" -extpass "--"`

Applies to: all actions that ask for a password.

BUG: In `-extpass -X`, the `-X` will be interpreted as `--X`. Please use
`-extpass=-X` to prevent that. See **Dash duplication** in the **BUGS** section
for details.

#### -fido2 DEVICE_PATH
Use a FIDO2 token to initialize and unlock the filesystem.
Use "fido2-token -L" to obtain the FIDO2 token device path.
For linux, "fido2-tools" package is needed.

Applies to: all actions that ask for a password.

#### -masterkey string
Use an explicit master key specified on the command line or, if the special
value "stdin" is used, read the masterkey from stdin, instead of reading
the config file and asking for the decryption password.

Note that the command line, and with it the master key, is visible to
anybody on the machine who can execute "ps -auxwww". Use "-masterkey=stdin"
to avoid that risk.

The masterkey option is meant as a recovery option for emergencies, such as
if you have forgotten the password or lost the config file.

Even if a config file exists, it will not be used. All non-standard
settings have to be passed on the command line: `-aessiv` when you
mount a filesystem that was created using reverse mode, or
`-plaintextnames` for a filesystem that was created with that option.

Examples:

    -masterkey=6f717d8b-6b5f8e8a-fd0aa206-778ec093-62c5669b-abd229cd-241e00cd-b4d6713d
    -masterkey=stdin

Applies to: all actions that ask for a password.

#### -memprofile string
Write memory profile to the specified file. This is useful when debugging
memory usage of gocryptfs.

Applies to: all actions.

#### -o COMMA-SEPARATED-OPTIONS
For compatibility with mount(1), options are also accepted as
"-o COMMA-SEPARATED-OPTIONS" at the end of the command line.
For example, "-o q,zerokey" is equivalent to passing "-q -zerokey".

Note that you can only use options that are understood by gocryptfs
with "-o". If you want to pass special flags to the kernel, you should
use "-ko" (*k*ernel *o*ption). This is different in libfuse-based
filesystems, that automatically pass any "-o" options they do not
understand along to the kernel.

Example:

    gocryptfs /tmp/foo /tmp/bar -o q,zerokey

Applies to: all actions.

#### -openssl bool/"auto"
Use OpenSSL instead of built-in Go crypto (default "auto"). Using
built-in crypto is 4x slower unless your CPU has AES instructions and
you are using Go 1.6+. In mode "auto", gocrypts chooses the faster
option.

Applies to: all actions.

#### -passfile FILE [-passfile FILE2 ...]
Read password from the specified plain text file. The file should contain exactly
one line (do not use binary files!).
A warning will be printed if there is more than one line, and only
the first line will be used. A single
trailing newline is allowed and does not cause a warning.

Pass this option multiple times to read the first line from multiple
files. They are concatenated for the effective password.

Example:

    echo hello > hello.txt
    echo word > world.txt
    gocryptfs -passfile hello.txt -passfile world.txt

The effective password will be "helloworld".

Applies to: all actions that ask for a password.

#### -q, -quiet
Quiet - silence informational messages.

Applies to: all actions.

#### -scryptn int
gocryptfs uses *scrypt* for hashing the password when mounting,
which protects from brute-force attacks.

`-scryptn` controls the *scrypt* cost parameter "N" expressed as scryptn=log2(N).
Possible values are `-scryptn=10` to `-scryptn=28`, representing N=2^10 to N=2^28.

Setting this to a lower
value speeds up mounting and reduces its memory needs, but makes
the password susceptible to brute-force attacks. The default is 16.

The memory usage for *scrypt* during mounting is as follows:

    scryptn     Memory Usage  
    =======     ============
    10          1   MiB
    11          2 
    12          4 
    13          8 
    14          16  
    15          32  
    16          64  
    17          128 
    18          256 
    19          512 
    20          1   GiB
    21          2 
    22          4 
    23          8 
    24          16  
    25          32  
    26          64  
    27          128 
    28          256 

Applies to: `-init`, `-passwd`

See also: the benchmarks in the gocryptfs source code in internal/configfile.

#### -trace string
Write execution trace to file. View the trace using "go tool trace FILE".

Applies to: all actions.

#### -wpanic
When encountering a warning, panic and exit immediately. This is
useful in regression testing.

Applies to: all actions.

#### \-\-
Stop option parsing. Helpful when CIPHERDIR may start with a
dash "-".

Applies to: all actions.

EXCLUDING FILES
===============

In reverse mode, it is possible to exclude files from the encrypted view, using
the `-exclude`, `-exclude-wildcard` and `-exclude-from` options.

`-exclude` matches complete paths, so `-exclude file.txt` only excludes a file
named `file.txt` in the root of the mounted filesystem; files named `file.txt`
in subdirectories are still visible. Wildcards are NOT supported.
This option is kept for compatibility with the behavior up to version 1.6.x.
New users should use `-exclude-wildcard` instead.

`-exclude-wildcard` uses gitignore syntax and matches files anywhere, so `-exclude-wildcard file.txt`
excludes files named `file.txt` in any directory. If you want to match complete
paths, you can prefix the filename with a `/`: `-exclude-wildcard /file.txt`
excludes only `file.txt` in the root of the mounted filesystem.

If there are many exclusions, you can use `-exclude-from` to read gitignore
patterns from a file. As with `-exclude-wildcard`, use a
leading `/` to match complete paths.

The rules for exclusion are that of [gitignore](https://git-scm.com/docs/gitignore#_pattern_format).
In short:

1. A blank line matches no files, so it can serve as a separator
   for readability.
2. A line starting with `#` serves as a comment. Put a backslash (`\`)
   in front of the first hash for patterns that begin with a hash.
3. Trailing spaces are ignored unless they are quoted with backslash (`\`).
4. An optional prefix `!` negates the pattern; any matching file
   excluded by a previous pattern will become included again. It is not
   possible to re-include a file if a parent directory of that file is
   excluded. Put a backslash (`\`) in front of the first `!` for
   patterns that begin with a literal `!`, for example, `\!important!.txt`.
5. If the pattern ends with a slash, it is removed for the purpose of the
   following description, but it would only find a match with a directory.
   In other words, `foo/` will match a directory foo and paths underneath it,
   but will not match a regular file or a symbolic link foo.
6. If the pattern does not contain a slash `/`, it is treated as a shell glob
   pattern and checked for a match against the pathname relative to the
   root of the mounted filesystem.
7. Otherwise, the pattern is treated as a shell glob suitable for
   consumption by fnmatch(3) with the FNM_PATHNAME flag: wildcards in the
   pattern will not match a `/` in the pathname. For example,
   `Documentation/*.html` matches `Documentation/git.html` but not
   `Documentation/ppc/ppc.html` or `tools/perf/Documentation/perf.html`.
8. A leading slash matches the beginning of the pathname. For example,
   `/*.c` matches `cat-file.c` but not `mozilla-sha1/sha1.c`.
9. Two consecutive asterisks (`**`) in patterns matched against full
   pathname may have special meaning:
    i.   A leading `**` followed by a slash means match in all directories.
         For example, `**/foo` matches file or directory `foo` anywhere,
         the same as pattern `foo`. `**/foo/bar` matches file or directory
         `bar` anywhere that is directly under directory `foo`.
    ii.  A trailing `/**` matches everything inside. For example, `abc/**`
         matches all files inside directory `abc`, with infinite depth.
    iii. A slash followed by two consecutive asterisks then a slash matches
         zero or more directories. For example, `a/**/b` matches `a/b`,
         `a/x/b`, `a/x/y/b` and so on.
    iv.  Other consecutive asterisks are considered invalid.


EXAMPLES
========

### Init

Create an encrypted filesystem in directory "mydir.crypt", mount it on "mydir":

	mkdir mydir.crypt mydir
	gocryptfs -init mydir.crypt
	gocryptfs mydir.crypt mydir

### Mount

Mount an encrypted view of joe's home directory using reverse mode:

	mkdir /home/joe.crypt
	gocryptfs -init -reverse /home/joe
	gocryptfs -reverse /home/joe /home/joe.crypt

### fstab

Adding this line to `/etc/fstab` will mount `/tmp/cipher` to `/tmp/plain` on boot, using the
password in `/tmp/passfile`. Use `sudo mount -av` to test the line without having
to reboot. Adjust the gocryptfs path acc. to the output of the command `which gocryptfs`.
Do use the `nofail` option to prevent an unbootable system if the gocryptfs mount fails (see
the `-nofail` option for details).

    /tmp/cipher /tmp/plain fuse./usr/local/bin/gocryptfs nofail,allow_other,passfile=/tmp/password 0 0

ENVIRONMENT VARIABLES
=====================

### NO_COLOR

If `NO_COLOR` is set (regardless of value), colored output is disabled (see https://no-color.org/).

EXIT CODES
==========

0: success  
6: CIPHERDIR is not an empty directory (on "-init")  
10: MOUNTPOINT is not an empty directory  
12: password incorrect  
22: password is empty (on "-init")  
23: could not read gocryptfs.conf  
24: could not write gocryptfs.conf (on "-init" or "-password")  
26: fsck found errors  
other: please check the error message

See also: https://github.com/rfjakob/gocryptfs/blob/master/internal/exitcodes/exitcodes.go

BUGS
====

### Dash duplication

gocryptfs v2.1 switched to the `pflag` library for command-line parsing
to support flags and positional arguments in any order. To stay compatible
with single-dash long options like `-extpass`, an ugly hack was added:
The command line is preprocessed, and all single-dash options are converted to
double-dash.

Unfortunately, this means that in

    gocryptfs -extpass myapp -extpass -X

gocryptfs transforms the `-X` to `--X`, and it will call `myapp --X` as the extpass program.

Please use

    gocryptfs -extpass myapp -extpass=-X

to work around this bug.

SEE ALSO
========
mount(2) fuse(8) fallocate(2) encfs(1) gitignore(5)
