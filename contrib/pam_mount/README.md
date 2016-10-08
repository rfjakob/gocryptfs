Mounting gocryptfs on login using pam_mount
===========================================

This works on Fedora 24 with active SELinux. Feedback on other platforms
is welcome.

gocryptfs
---------

Copy the `gocryptfs` binary and `gocryptfs_pam_mount.bash` into
`/usr/local/bin` .

The bash wrapper is neccessary because of the different calling
conventions between pam_mount and gocryptfs.

Create a gocryptfs filesystem:
```
$ mkdir /home/testuser/cipher /home/testuser/plain
$ gocryptfs -init /home/testuser/cipher
```

pam_mount config
----------------

Put the following into `/etc/security/pam_mount.conf.xml`, just before
the closing `</pam_mount>` tag at the bottom:

```
<volume user="testuser" fstype="fuse" options="defaults"
path="/usr/local/bin/gocryptfs_pam_mount.bash#/home/%(USER)/cipher"
mountpoint="/home/%(USER)/plain" />
```

If you want to disable the display of the masterkey on mount, replace
`options="defaults"` with `options="quiet"`.

PAM config
----------

An example `/etc/pam.d/login` on Fedora 24 is shown below. pam_mount
MUST be called AFTER `pam_selinux.so open` because that puts us in the
right SELinux context.

```
#%PAM-1.0
auth       substack     system-auth
auth       include      postlogin
account    required     pam_nologin.so
account    include      system-auth
password   include      system-auth
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_console.so
session    required     pam_selinux.so open
session    required     pam_namespace.so
# vvv insert pam_mount here
session optional pam_mount.so
# ^^^ insert pam_mount here
session    optional     pam_keyinit.so force revoke
session    include      system-auth
session    include      postlogin
-session   optional     pam_ck_connector.so
```
