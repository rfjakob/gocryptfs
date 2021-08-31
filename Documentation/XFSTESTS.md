# xfstests results

Results of running [fuse-xfstests](https://github.com/rfjakob/fuse-xfstests)
against gocryptfs.

## Failures

### generic/035

Known [issue](https://github.com/hanwen/go-fuse/issues/55) in the
go-fuse library. Unlikely to have real-world impact.

### generic/062

Only `user.\*` xattrs are supported, others are rejected.

### generic/093

`security.\*` xattrs are not supported.

### generic/097

`trusted.\*` xattrs are not supported.

### generic/228

`ulimit -f` is not implemented in gocryptfs.

### generic/273

Needs further analysis:
```
_porter 28 not complete
cp: cannot create regular file '/var/tmp/check-gocryptfs/scratchdir/sub_28/origin/file_548': No such file or directory
```

### generic/403

`trusted.\*` xattrs are not supported.

### generic/426, generic/467, generic/477

Needs further analysis.

Failure related to the new system call open_by_handle_at(2)
([lwn article](https://lwn.net/Articles/375888/)).

### generic/466

Harmless output caused by the fact that gocryptfs is not backed by
a block device.

### generic/484

Needs further analysis: `record lock is not preserved across execve(2)`

### generic/488

Needs further analysis: `Too many open files`

## Full Test Output

```
0 jakob@brikett:~/code/fuse-xfstests$ sudo ./check-gocryptfs
gocryptfs v1.7.1; go-fuse v2.0.2-4-g8458b8a; 2019-10-10 go1.12.9 linux/amd64
fuse-xfstests nlink0/dff383ab
Thu 10 Oct 2019 08:31:43 PM UTC

FSTYP         -- fuse.gocryptfs
PLATFORM      -- Linux/x86_64 brikett 5.2.17-200.fc30.x86_64
MKFS_OPTIONS  -- /var/tmp/check-gocryptfs/scratchdev
MOUNT_OPTIONS -- -o context=system_u:object_r:root_t:s0 /var/tmp/check-gocryptfs/scratchdev /var/tmp/check-gocryptfs/scratchdir

generic/001 6s ...  5s
generic/002 14s ...  1s
generic/003 [not run] atime related mount options have no effect on fuse.gocryptfs
generic/004 [not run] O_TMPFILE is not supported
generic/005 14s ...  0s
generic/006 16s ...  3s
generic/007 19s ...  7s
generic/008 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/009 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/010 15s ...  1s
generic/011 18s ...  4s
generic/012 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/013 97s ...  12s
generic/014 16s ...  2s
generic/015 2s ...  1s
generic/016 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/017 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/018 [not run] defragmentation not supported for fstype "fuse.gocryptfs"
generic/020 14s ...  1s
generic/021 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/022 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/023 15s ...  1s
generic/024 [not run] fs doesn't support RENAME_NOREPLACE
generic/025 [not run] fs doesn't support RENAME_EXCHANGE
generic/026 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/027 269s ...  101s
generic/028 19s ...  6s
generic/029 0s ...  0s
generic/030 2s ...  1s
generic/031 [not run] xfs_io fcollapse failed (old kernel/wrong fs?)
generic/032 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/033 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/034 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/035 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/035.out.bad)
    --- tests/generic/035.out   2018-01-20 14:29:39.062451937 +0100
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/035.out.bad 2019-10-10 22:34:13.622100130 +0200
    @@ -1,3 +1,7 @@
     QA output created by 035
     overwriting regular file:
    +nlink is 1, should be 0
    +res=0 dev=54 ino=5770027 mode=100644 nlink=1 uid=0
     overwriting directory:
    +t_rename_overwrite: fstat(3): No such file or directory
    +res=-1 dev=0 ino=0 mode=0 nlink=0 uid=0
    ...
    (Run 'diff -u tests/generic/035.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/035.out.bad'  to see the entire diff)
generic/036 24s ...  10s
generic/037 5s ...  3s
generic/038 [not run] This test requires at least 10GB free on /var/tmp/check-gocryptfs/scratchdir to run
generic/039 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/040 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/041 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/043 [not run] fuse.gocryptfs does not support shutdown
generic/044 [not run] fuse.gocryptfs does not support shutdown
generic/045 [not run] fuse.gocryptfs does not support shutdown
generic/046 [not run] fuse.gocryptfs does not support shutdown
generic/047 [not run] fuse.gocryptfs does not support shutdown
generic/048 [not run] fuse.gocryptfs does not support shutdown
generic/049 [not run] fuse.gocryptfs does not support shutdown
generic/050 [not run] fuse.gocryptfs does not support shutdown
generic/051 [not run] fuse.gocryptfs does not support shutdown
generic/052 [not run] fuse.gocryptfs does not support shutdown
generic/053 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/054 [not run] fuse.gocryptfs does not support shutdown
generic/055 [not run] fuse.gocryptfs does not support shutdown
generic/056 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/057 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/058 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/059 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/060 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/061 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/062 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/062.out.bad)
    --- tests/generic/062.out   2018-01-20 14:29:39.067451950 +0100
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/062.out.bad 2019-10-10 22:34:34.290196880 +0200
    @@ -13,7 +13,7 @@

     *** set/get one initially empty attribute
     # file: SCRATCH_MNT/reg
    -user.name
    +user.name=""

     *** overwrite empty, set several new attributes
    ...
    (Run 'diff -u tests/generic/062.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/062.out.bad'  to see the entire diff)
generic/063 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/064 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/065 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/066 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/067 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/068 [not run] fuse.gocryptfs does not support freezing
generic/069 221s ...  216s
generic/070 22s ...  9s
generic/071 1s ...  1s
generic/072 [not run] xfs_io fcollapse failed (old kernel/wrong fs?)
generic/073 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/074 766s ...  328s
generic/075 69s ...  11s
generic/076 [not run] require /var/tmp/check-gocryptfs/scratchdev to be local device
generic/077 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/078 [not run] fs doesn't support RENAME_WHITEOUT
generic/079 [not run] file system doesn't support chattr +ia
generic/080 16s ...  2s
generic/081 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/082 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/083 15s ...  8s
generic/084 6s ...  5s
generic/085 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/086 15s ...  1s
generic/087 14s ...  0s
generic/088 14s ...  0s
generic/089 48s ...  53s
generic/090 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/091 19s ...  5s
generic/092 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/093 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/093.out.bad)
    --- tests/generic/093.out   2018-06-27 21:12:13.629235005 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/093.out.bad 2019-10-10 22:45:22.194059446 +0200
    @@ -1,15 +1,22 @@
     QA output created by 093

     **** Verifying that appending to file clears capabilities ****
    -file = cap_chown+ep
    +Failed to set capabilities on file '/var/tmp/check-gocryptfs/testdir/093.file' (Operation not supported)
    +usage: setcap [-q] [-v] [-n <rootid>] (-r|-|<caps>) <filename> [ ... (-r|-|<capsN>) <filenameN> ]
    +
    ...
    (Run 'diff -u tests/generic/093.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/093.out.bad'  to see the entire diff)
generic/094 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/095 [not run] fio utility required, skipped this test
generic/096 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/097 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/097.out.bad)
    --- tests/generic/097.out   2018-06-27 21:12:13.630235009 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/097.out.bad 2019-10-10 22:45:23.382064979 +0200
    @@ -110,18 +110,16 @@
     *** Test out the trusted namespace ***

     set EA <trusted:colour,marone>:
    +setfattr: TEST_DIR/foo: Operation not supported

     set EA <user:colour,beige>:

    ...
    (Run 'diff -u tests/generic/097.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/097.out.bad'  to see the entire diff)
generic/098 1s ...  0s
generic/099 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/100 31s ...  15s
generic/101 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/102 32s ...  20s
generic/103 2s ...  2s
generic/104 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/105 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/106 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/107 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/108 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/109 3s ...  4s
generic/110 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/111 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/112 72s ...  14s
generic/113 155s ...  38s
generic/114 [not run] device block size: 4096 greater than 512
generic/115 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/116 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/117 8s ...  10s
generic/118 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/119 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/120 [not run] atime related mount options have no effect on fuse.gocryptfs
generic/121 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/122 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/123 15s ...  1s
generic/124 19s ...  4s
generic/126 15s ...  1s
generic/127 540s ...  458s
generic/128 1s ...  0s
generic/129 43s ...  33s
generic/130 4s ...  5s
generic/131 16s ...  2s
generic/132 26s ...  17s
generic/133 79s ...  22s
generic/134 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/135 0s ...  1s
generic/136 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/137 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/138 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/139 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/140 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/141 1s ...  0s
generic/142 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/143 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/144 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/145 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/146 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/147 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/148 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/149 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/150 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/151 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/152 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/153 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/154 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/155 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/156 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/157 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/158 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/159 [not run] file system doesn't support chattr +i
generic/160 [not run] file system doesn't support chattr +i
generic/161 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/162 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/163 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/164 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/165 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/166 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/167 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/168 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/169 1s ...  1s
generic/170 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/171 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/172 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/173 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/174 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/175 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/176 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/177 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/178 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/179 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/180 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/181 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/182 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/183 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/184 16s ...  0s
generic/185 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/186 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/187 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/188 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/189 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/190 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/191 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/192 [not run] atime related mount options have no effect on fuse.gocryptfs
generic/193 16s ...  1s
generic/194 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/195 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/196 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/197 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/198 17s ...  1s
generic/199 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/200 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/201 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/202 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/203 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/204 20s ...  16s
generic/205 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/206 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/207 15s ...  1s
generic/208 216s ...  201s
generic/209 46s ...  31s
generic/210 15s ...  1s
generic/211 15s ...  1s
generic/212 15s ...  1s
generic/213 47s ...  20s
generic/214 15s ...  1s
generic/215 17s ...  4s
generic/216 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/217 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/218 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/219 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/220 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/221 17s ...  2s
generic/222 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/223 [not run] can't mkfs fuse.gocryptfs with geometry
generic/224 129s ...  34s
generic/225 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/226 14s ...  12s
generic/227 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/228  1s
generic/229 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/230 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/231 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/232 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/233 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/234 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/235 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/236 17s ...  2s
generic/237 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/238 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/239 21s ...  10s
generic/240 [not run] fs block size must be larger than the device block size.  fs block size: 4096, device block size: 4096
generic/241 87s ...  74s
generic/242 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/243 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/244 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/245 15s ...  1s
generic/246 16s ...  2s
generic/247 32s ...  13s
generic/248 12s ...  2s
generic/249 14s ...  4s
generic/250 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/252 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/253 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/254 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/255 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/256 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/257 12s ...  3s
generic/258 12s ...  2s
generic/259 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/260 [not run] FITRIM not supported on /var/tmp/check-gocryptfs/scratchdir
generic/261 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/262 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/263 30s ...  22s
generic/264 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/265 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/266 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/267 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/268 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/269 34s ...  29s
generic/270 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/271 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/272 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/273 56s ...  42s
generic/274 42s ...  50s
generic/275 46s ...  54s
generic/276 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/277 [not run] file system doesn't support chattr +A
generic/278 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/279 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/280 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/281 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/282 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/283 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/284 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/285 12s ...  3s
generic/286 35s ...  26s
generic/287 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/288 [not run] FITRIM not supported on /var/tmp/check-gocryptfs/scratchdir
generic/289 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/290 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/291 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/292 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/293 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/294 0s ...  1s
generic/295 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/296 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/297 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/298 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/299 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/300 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/301 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/302 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/303 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/304 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/305 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/306 12s ...  3s
generic/307 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/308 11s ...  2s
generic/309 13s ...  4s
generic/310 76s ...  69s
generic/311 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/312 2s ...  1s
generic/313 14s ...  7s
generic/314 11s ...  2s
generic/315 10s ...  3s
generic/316 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/317 0s ...  1s
generic/318 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/319 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/320 59s ...  48s
generic/321 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/322 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/323 131s ...  123s
generic/324 [not run] defragmentation not supported for fstype "fuse.gocryptfs"
generic/325 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/326 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/327 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/328 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/329 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/330 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/331 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/332 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/333 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/334 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/335 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/336 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/337 0s ...  0s
generic/338 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/339 13s ...  17s
generic/340 9s ...  4s
generic/341 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/342 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/343 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/344 36s ...  24s
generic/345 18s ...  8s
generic/346 29s ...  22s
generic/347 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/348 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/352 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/353 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/354 7s ...  5s
generic/355 11s ...  3s
generic/356 [not run] swapfiles are not supported
generic/357 [not run] swapfiles are not supported
generic/358 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/359 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/360 10s ...  2s
generic/361 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/362 [not run] this test requires richacl support on $SCRATCH_DEV
generic/363 [not run] this test requires richacl support on $SCRATCH_DEV
generic/364 [not run] this test requires richacl support on $SCRATCH_DEV
generic/365 [not run] this test requires richacl support on $SCRATCH_DEV
generic/366 [not run] this test requires richacl support on $SCRATCH_DEV
generic/367 [not run] this test requires richacl support on $SCRATCH_DEV
generic/368 [not run] this test requires richacl support on $SCRATCH_DEV
generic/369 [not run] this test requires richacl support on $SCRATCH_DEV
generic/370 [not run] this test requires richacl support on $SCRATCH_DEV
generic/371 159s ...  145s
generic/372 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/373 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/374 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/375 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/376 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/377 0s ...  0s
generic/378 11s ...  2s
generic/379 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/380 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/381 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/382 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/383 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/384 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/385 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/386 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/387 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/388 [not run] require /var/tmp/check-gocryptfs/scratchdev to be local device
generic/389 [not run] O_TMPFILE is not supported
generic/390 [not run] fuse.gocryptfs does not support freezing
generic/391 19s ...  9s
generic/392 [not run] fuse.gocryptfs does not support shutdown
generic/393 0s ...  1s
generic/394 16s ...  4s
generic/395 [not run] No encryption support for fuse.gocryptfs
generic/396 [not run] No encryption support for fuse.gocryptfs
generic/397 [not run] No encryption support for fuse.gocryptfs
generic/398 [not run] No encryption support for fuse.gocryptfs
generic/399 [not run] No encryption support for fuse.gocryptfs
generic/400 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/401 0s ...  0s
generic/402 [not run] no kernel support for y2038 sysfs switch
generic/403 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/403.out.bad)
    --- tests/generic/403.out   2018-06-27 21:12:13.659235117 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/403.out.bad 2019-10-10 23:16:53.291612884 +0200
    @@ -1,2 +1,204 @@
     QA output created by 403
    +setfattr: /var/tmp/check-gocryptfs/scratchdir/file: Operation not supported
    +/var/tmp/check-gocryptfs/scratchdir/file: trusted.small: Operation not supported
    +setfattr: /var/tmp/check-gocryptfs/scratchdir/file: Operation not supported
    +setfattr: /var/tmp/check-gocryptfs/scratchdir/file: Operation not supported
    +setfattr: /var/tmp/check-gocryptfs/scratchdir/file: Operation not supported
    +setfattr: /var/tmp/check-gocryptfs/scratchdir/file: Operation not supported
    ...
    (Run 'diff -u tests/generic/403.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/403.out.bad'  to see the entire diff)
generic/404 [not run] xfs_io finsert failed (old kernel/wrong fs?)
generic/405 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/406 3s ...  2s
generic/407 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/408 [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/409 [not run] require /var/tmp/check-gocryptfs/scratchdev to be local device
generic/410 [not run] require /var/tmp/check-gocryptfs/scratchdev to be local device
generic/411 [not run] require /var/tmp/check-gocryptfs/scratchdev to be local device
generic/412 2s ...  3s
generic/413 [not run] /var/tmp/check-gocryptfs/scratchdev fuse.gocryptfs does not support -o dax
generic/414 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/415 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/416 105s ...  102s
generic/417 [not run] fuse.gocryptfs does not support shutdown
generic/418 [not run] require /var/tmp/check-gocryptfs/testdev to be valid block disk
generic/419 [not run] No encryption support for fuse.gocryptfs
generic/420 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/421 [not run] No encryption support for fuse.gocryptfs
generic/422 15s ...  3s
generic/423 15s ...  4s
generic/424 [not run] file system doesn't support any of /usr/bin/chattr +a/+c/+d/+i
generic/425 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/426 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/426.out.bad)
    --- tests/generic/426.out   2018-06-27 21:12:13.662235128 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/426.out.bad 2019-10-10 23:18:59.149149787 +0200
    @@ -1,5 +1,3077 @@
     QA output created by 426
     test_file_handles TEST_DIR/426-dir -d
     test_file_handles TEST_DIR/426-dir
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/426-dir/file000000) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/426-dir/file000001) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/426-dir/file000002) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/426-dir/file000003) returned 116 incorrectly on a linked file!
    ...
    (Run 'diff -u tests/generic/426.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/426.out.bad'  to see the entire diff)
generic/427 6s ...  4s
generic/428 15s ...  4s
generic/429 [not run] No encryption support for fuse.gocryptfs
generic/430 15s ...  4s
generic/431 15s ...  4s
generic/432 15s ...  4s
generic/433 15s ...  3s
generic/434 15s ...  4s
generic/435 [not run] No encryption support for fuse.gocryptfs
generic/436 15s ...  4s
generic/437 16s ...  4s
generic/438 57s ...  40s
generic/439 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/440 [not run] No encryption support for fuse.gocryptfs
generic/441 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/443 15s ...  4s
generic/444 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/445 15s ...  4s
generic/446 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/447 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/448 15s ...  4s
generic/449 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/450 [not run] Only test on sector size < half of block size
generic/451 45s ...  34s
generic/452 0s ...  0s
generic/453 1s ...  1s
generic/454 1s ...  1s
generic/455 [not run] This test requires a valid $LOGWRITES_DEV
generic/456 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/457 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/458 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/459 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/460 [not run] This test requires at least 1GB free on /var/tmp/check-gocryptfs/scratchdir to run
generic/461 [not run] fuse.gocryptfs does not support shutdown
generic/462 [not run] /var/tmp/check-gocryptfs/scratchdev fuse.gocryptfs does not support -o dax
generic/463 [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/464 94s ...  63s
generic/465 5s ...  2s
generic/466 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/466.out.bad)
    --- tests/generic/466.out   2018-06-27 21:12:13.667235146 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/466.out.bad 2019-10-10 23:22:14.813984485 +0200
    @@ -1,2 +1,3 @@
     QA output created by 466
     Silence is golden
    +blockdev: ioctl error on BLKGETSIZE64: Inappropriate ioctl for device
    ...
    (Run 'diff -u tests/generic/466.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/466.out.bad'  to see the entire diff)
generic/467 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/467.out.bad)
    --- tests/generic/467.out   2018-06-27 21:12:13.667235146 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/467.out.bad 2019-10-10 23:22:22.324016522 +0200
    @@ -1,9 +1,82 @@
     QA output created by 467
     test_file_handles TEST_DIR/467-dir -dp
     test_file_handles TEST_DIR/467-dir -rp
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/467-dir/file000000) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/467-dir/file000001) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/467-dir/file000002) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/467-dir/file000003) returned 116 incorrectly on a linked file!
    ...
    (Run 'diff -u tests/generic/467.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/467.out.bad'  to see the entire diff)
generic/468 [not run] fuse.gocryptfs does not support shutdown
generic/469 16s ...  4s
generic/470 [not run] This test requires a valid $LOGWRITES_DEV
generic/471 [not run] xfs_io pwrite failed (old kernel/wrong fs?)
generic/472 [not run] swapfiles are not supported
generic/474 [not run] fuse.gocryptfs does not support shutdown
generic/475 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/476 979s ...  940s
generic/477 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/477.out.bad)
    --- tests/generic/477.out   2018-06-27 21:12:13.669235154 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/477.out.bad 2019-10-10 23:38:15.586197915 +0200
    @@ -1,5 +1,48 @@
     QA output created by 477
     test_file_handles after cycle mount
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/file000000) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/file000001) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/file000002) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/file000003) returned 116 incorrectly on a linked file!
    +open_by_handle(/var/tmp/check-gocryptfs/testdir/file000004) returned 116 incorrectly on a linked file!
    ...
    (Run 'diff -u tests/generic/477.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/477.out.bad'  to see the entire diff)
generic/478 44s ...  35s
generic/479 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/480 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/481 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/482 [not run] This test requires a valid $LOGWRITES_DEV
generic/483 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/484 - output mismatch (see /home/jakob.donotbackup/code/fuse-xfstests/results//generic/484.out.bad)
    --- tests/generic/484.out   2018-06-27 21:12:13.676235180 +0200
    +++ /home/jakob.donotbackup/code/fuse-xfstests/results//generic/484.out.bad 2019-10-10 23:38:54.996371174 +0200
    @@ -1,2 +1,3 @@
     QA output created by 484
    +record lock is not preserved across execve(2)
     Silence is golden
    ...
    (Run 'diff -u tests/generic/484.out /home/jakob.donotbackup/code/fuse-xfstests/results//generic/484.out.bad'  to see the entire diff)
generic/485 [not run] xfs_io finsert failed (old kernel/wrong fs?)
generic/486 0s ...  0s
generic/487 [not run] This test requires a valid $SCRATCH_LOGDEV
generic/488 1s ...  2s
generic/489 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/490 15s ...  3s
generic/491 [not run] fuse.gocryptfs does not support freezing
generic/492 [not run] xfs_io label support is missing (missing syscall?)
generic/493 [not run] swapfiles are not supported
generic/494 [not run] swapfiles are not supported
generic/495 [not run] swapfiles are not supported
generic/496 [not run] swapfiles are not supported
generic/497 [not run] swapfiles are not supported
generic/498 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/499 [not run] xfs_io fcollapse failed (old kernel/wrong fs?)
generic/500 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/501 [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/502 [not run] require /var/tmp/check-gocryptfs/scratchdev to be valid block disk
generic/503 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/504 15s ...  3s
shared/001  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/002  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/003  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/004  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/006  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/008  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/009  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/010  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/032  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/272  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/289  [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/298  [not run] not suitable for this filesystem type: fuse.gocryptfs
Ran: generic/001 generic/002 generic/003 generic/004 generic/005 generic/006 generic/007 generic/008 generic/009 generic/010 generic/011 generic/012 generic/013 generic/014 generic/015 generic/016 generic/017 generic/018 generic/020 generic/021 generic/022 generic/023 generic/024 generic/025 generic/026 generic/027 generic/028 generic/029 generic/030 generic/031 generic/032 generic/033 generic/034 generic/035 generic/036 generic/037 generic/038 generic/039 generic/040 generic/041 generic/043 generic/044 generic/045 generic/046 generic/047 generic/048 generic/049 generic/050 generic/051 generic/052 generic/053 generic/054 generic/055 generic/056 generic/057 generic/058 generic/059 generic/060 generic/061 generic/062 generic/063 generic/064 generic/065 generic/066 generic/067 generic/068 generic/069 generic/070 generic/071 generic/072 generic/073 generic/074 generic/075 generic/076 generic/077 generic/078 generic/079 generic/080 generic/081 generic/082 generic/083 generic/084 generic/085 generic/086 generic/087 generic/088 generic/089 generic/090 generic/091 generic/092 generic/093 generic/094 generic/095 generic/096 generic/097 generic/098 generic/099 generic/100 generic/101 generic/102 generic/103 generic/104 generic/105 generic/106 generic/107 generic/108 generic/109 generic/110 generic/111 generic/112 generic/113 generic/114 generic/115 generic/116 generic/117 generic/118 generic/119 generic/120 generic/121 generic/122 generic/123 generic/124 generic/126 generic/127 generic/128 generic/129 generic/130 generic/131 generic/132 generic/133 generic/134 generic/135 generic/136 generic/137 generic/138 generic/139 generic/140 generic/141 generic/142 generic/143 generic/144 generic/145 generic/146 generic/147 generic/148 generic/149 generic/150 generic/151 generic/152 generic/153 generic/154 generic/155 generic/156 generic/157 generic/158 generic/159 generic/160 generic/161 generic/162 generic/163 generic/164 generic/165 generic/166 generic/167 generic/168 generic/169 generic/170 generic/171 generic/172 generic/173 generic/174 generic/175 generic/176 generic/177 generic/178 generic/179 generic/180 generic/181 generic/182 generic/183 generic/184 generic/185 generic/186 generic/187 generic/188 generic/189 generic/190 generic/191 generic/192 generic/193 generic/194 generic/195 generic/196 generic/197 generic/198 generic/199 generic/200 generic/201 generic/202 generic/203 generic/204 generic/205 generic/206 generic/207 generic/208 generic/209 generic/210 generic/211 generic/212 generic/213 generic/214 generic/215 generic/216 generic/217 generic/218 generic/219 generic/220 generic/221 generic/222 generic/223 generic/224 generic/225 generic/226 generic/227 generic/228 generic/229 generic/230 generic/231 generic/232 generic/233 generic/234 generic/235 generic/236 generic/237 generic/238 generic/239 generic/240 generic/241 generic/242 generic/243 generic/244 generic/245 generic/246 generic/247 generic/248 generic/249 generic/250 generic/252 generic/253 generic/254 generic/255 generic/256 generic/257 generic/258 generic/259 generic/260 generic/261 generic/262 generic/263 generic/264 generic/265 generic/266 generic/267 generic/268 generic/269 generic/270 generic/271 generic/272 generic/273 generic/274 generic/275 generic/276 generic/277 generic/278 generic/279 generic/280 generic/281 generic/282 generic/283 generic/284 generic/285 generic/286 generic/287 generic/288 generic/289 generic/290 generic/291 generic/292 generic/293 generic/294 generic/295 generic/296 generic/297 generic/298 generic/299 generic/300 generic/301 generic/302 generic/303 generic/304 generic/305 generic/306 generic/307 generic/308 generic/309 generic/310 generic/311 generic/312 generic/313 generic/314 generic/315 generic/316 generic/317 generic/318 generic/319 generic/320 generic/321 generic/322 generic/323 generic/324 generic/325 generic/326 generic/327 generic/328 generic/329 generic/330 generic/331 generic/332 generic/333 generic/334 generic/335 generic/336 generic/337 generic/338 generic/339 generic/340 generic/341 generic/342 generic/343 generic/344 generic/345 generic/346 generic/347 generic/348 generic/352 generic/353 generic/354 generic/355 generic/356 generic/357 generic/358 generic/359 generic/360 generic/361 generic/362 generic/363 generic/364 generic/365 generic/366 generic/367 generic/368 generic/369 generic/370 generic/371 generic/372 generic/373 generic/374 generic/375 generic/376 generic/377 generic/378 generic/379 generic/380 generic/381 generic/382 generic/383 generic/384 generic/385 generic/386 generic/387 generic/388 generic/389 generic/390 generic/391 generic/392 generic/393 generic/394 generic/395 generic/396 generic/397 generic/398 generic/399 generic/400 generic/401 generic/402 generic/403 generic/404 generic/405 generic/406 generic/407 generic/408 generic/409 generic/410 generic/411 generic/412 generic/413 generic/414 generic/415 generic/416 generic/417 generic/418 generic/419 generic/420 generic/421 generic/422 generic/423 generic/424 generic/425 generic/426 generic/427 generic/428 generic/429 generic/430 generic/431 generic/432 generic/433 generic/434 generic/435 generic/436 generic/437 generic/438 generic/439 generic/440 generic/441 generic/443 generic/444 generic/445 generic/446 generic/447 generic/448 generic/449 generic/450 generic/451 generic/452 generic/453 generic/454 generic/455 generic/456 generic/457 generic/458 generic/459 generic/460 generic/461 generic/462 generic/463 generic/464 generic/465 generic/466 generic/467 generic/468 generic/469 generic/470 generic/471 generic/472 generic/474 generic/475 generic/476 generic/477 generic/478 generic/479 generic/480 generic/481 generic/482 generic/483 generic/484 generic/485 generic/486 generic/487 generic/488 generic/489 generic/490 generic/491 generic/492 generic/493 generic/494 generic/495 generic/496 generic/497 generic/498 generic/499 generic/500 generic/501 generic/502 generic/503 generic/504 shared/001 shared/002 shared/003 shared/004 shared/006 shared/008 shared/009 shared/010 shared/032 shared/272 shared/289 shared/298
Not run: generic/003 generic/004 generic/008 generic/009 generic/012 generic/016 generic/017 generic/018 generic/021 generic/022 generic/024 generic/025 generic/026 generic/031 generic/032 generic/033 generic/034 generic/038 generic/039 generic/040 generic/041 generic/043 generic/044 generic/045 generic/046 generic/047 generic/048 generic/049 generic/050 generic/051 generic/052 generic/053 generic/054 generic/055 generic/056 generic/057 generic/058 generic/059 generic/060 generic/061 generic/063 generic/064 generic/065 generic/066 generic/067 generic/068 generic/072 generic/073 generic/076 generic/077 generic/078 generic/079 generic/081 generic/082 generic/085 generic/090 generic/092 generic/094 generic/095 generic/096 generic/099 generic/101 generic/104 generic/105 generic/106 generic/107 generic/108 generic/110 generic/111 generic/114 generic/115 generic/116 generic/118 generic/119 generic/120 generic/121 generic/122 generic/134 generic/136 generic/137 generic/138 generic/139 generic/140 generic/142 generic/143 generic/144 generic/145 generic/146 generic/147 generic/148 generic/149 generic/150 generic/151 generic/152 generic/153 generic/154 generic/155 generic/156 generic/157 generic/158 generic/159 generic/160 generic/161 generic/162 generic/163 generic/164 generic/165 generic/166 generic/167 generic/168 generic/170 generic/171 generic/172 generic/173 generic/174 generic/175 generic/176 generic/177 generic/178 generic/179 generic/180 generic/181 generic/182 generic/183 generic/185 generic/186 generic/187 generic/188 generic/189 generic/190 generic/191 generic/192 generic/194 generic/195 generic/196 generic/197 generic/199 generic/200 generic/201 generic/202 generic/203 generic/205 generic/206 generic/216 generic/217 generic/218 generic/219 generic/220 generic/222 generic/223 generic/225 generic/227 generic/229 generic/230 generic/231 generic/232 generic/233 generic/234 generic/235 generic/237 generic/238 generic/240 generic/242 generic/243 generic/244 generic/250 generic/252 generic/253 generic/254 generic/255 generic/256 generic/259 generic/260 generic/261 generic/262 generic/264 generic/265 generic/266 generic/267 generic/268 generic/270 generic/271 generic/272 generic/276 generic/277 generic/278 generic/279 generic/280 generic/281 generic/282 generic/283 generic/284 generic/287 generic/288 generic/289 generic/290 generic/291 generic/292 generic/293 generic/295 generic/296 generic/297 generic/298 generic/299 generic/300 generic/301 generic/302 generic/303 generic/304 generic/305 generic/307 generic/311 generic/316 generic/318 generic/319 generic/321 generic/322 generic/324 generic/325 generic/326 generic/327 generic/328 generic/329 generic/330 generic/331 generic/332 generic/333 generic/334 generic/335 generic/336 generic/338 generic/341 generic/342 generic/343 generic/347 generic/348 generic/352 generic/353 generic/356 generic/357 generic/358 generic/359 generic/361 generic/362 generic/363 generic/364 generic/365 generic/366 generic/367 generic/368 generic/369 generic/370 generic/372 generic/373 generic/374 generic/375 generic/376 generic/379 generic/380 generic/381 generic/382 generic/383 generic/384 generic/385 generic/386 generic/387 generic/388 generic/389 generic/390 generic/392 generic/395 generic/396 generic/397 generic/398 generic/399 generic/400 generic/402 generic/404 generic/405 generic/407 generic/408 generic/409 generic/410 generic/411 generic/413 generic/414 generic/415 generic/417 generic/418 generic/419 generic/420 generic/421 generic/424 generic/425 generic/429 generic/435 generic/439 generic/440 generic/441 generic/444 generic/446 generic/447 generic/449 generic/450 generic/455 generic/456 generic/457 generic/458 generic/459 generic/460 generic/461 generic/462 generic/463 generic/468 generic/470 generic/471 generic/472 generic/474 generic/475 generic/479 generic/480 generic/481 generic/482 generic/483 generic/485 generic/487 generic/489 generic/491 generic/492 generic/493 generic/494 generic/495 generic/496 generic/497 generic/498 generic/499 generic/500 generic/501 generic/502 generic/503 shared/001 shared/002 shared/003 shared/004 shared/006 shared/008 shared/009 shared/010 shared/032 shared/272 shared/289 shared/298
Failures: generic/035 generic/062 generic/093 generic/097 generic/403 generic/426 generic/466 generic/467 generic/477 generic/484
Failed 10 of 507 tests

Runtime was 4046 seconds
```
