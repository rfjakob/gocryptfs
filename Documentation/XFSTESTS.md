# xfstests results

Results of running [fuse-xfstests](https://github.com/rfjakob/fuse-xfstests)
against gocryptfs.

## Failures

### generic/035

Known [issue](https://github.com/hanwen/go-fuse/issues/55) in the
go-fuse library. Unlikely to have real-world impact.

### generic/069

False negative due to harmless log output from go-fuse.

### generic/084

False negative due to harmless log output from go-fuse.

### generic/228

"ulimit -f" is not implemented in gocryptfs.

### generic/317

User namespaces inside gocryptfs are not supported (yet? use cases?)

### generic/391

O_DIRECT is not supported by gocryptfs.

### generic/426

Failure related to the new system call open_by_handle_at(2)
([lwn article](https://lwn.net/Articles/375888/)). open_by_handle_at
is currently not supported by gocryptfs.

## Full Test Output

```
$ sudo ./check-gocryptfs 
gocryptfs v1.4.2-72-g991708a-dirty; go-fuse v20170619-24-g3d30ad6; 2018-01-21 go1.9.2
fuse-xfstests gocryptfs-2017-08-08/9c46b7cd
Sun Jan 21 19:07:09 UTC 2018

FSTYP         -- fuse.gocryptfs
PLATFORM      -- Linux/x86_64 brikett 4.14.11-300.fc27.x86_64
MKFS_OPTIONS  -- /tmp/check-gocryptfs/scratchdev
MOUNT_OPTIONS -- -o context=system_u:object_r:root_t:s0 /tmp/check-gocryptfs/scratchdev /tmp/check-gocryptfs/scratchdir

generic/001 5s ... 5s
generic/002 0s ... 1s
generic/003  [not run] atime related mount options have no effect on gocryptfs
generic/004  [not run] xfs_io flink failed (old kernel/wrong fs?)
generic/005 1s ... 0s
generic/006 1s ... 2s
generic/007 3s ... 4s
generic/008  [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/009  [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/010  [not run] src/dbtest not built
generic/011 4s ...ino168268480 fh-1: Truncate on released file
 4s
generic/012 fallocate: only mode 0 (default) and 1 (keep size) are supported
 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/013 7s ... 7s
generic/014 2s ... 1s
generic/015  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/016  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/017  [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/018  [not run] defragmentation not supported for fstype "fuse.gocryptfs"
generic/019  [not run] /sys/kernel/debug/fail_make_request  not found. Seems that CONFIG_FAIL_MAKE_REQUEST kernel config option not enabled
generic/020  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/021  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/022  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/023 0s ... 1s
generic/024  [not run] fs doesn't support RENAME_NOREPLACE
generic/025  [not run] fs doesn't support RENAME_EXCHANGE
generic/026  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/027  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/028 5s ... 5s
generic/029 1s ... 0s
generic/030 1s ... 1s
generic/031  [not run] xfs_io fcollapse failed (old kernel/wrong fs?)
generic/032  [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/033  [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/034  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/035  - output mismatch (see /home/jakob/code/fuse-xfstests/results//generic/035.out.bad)
    --- tests/generic/035.out   2018-01-20 14:29:39.062451937 +0100
    +++ /home/jakob/code/fuse-xfstests/results//generic/035.out.bad 2018-01-21 20:07:45.460054934 +0100
    @@ -1,3 +1,5 @@
     QA output created by 035
     overwriting regular file:
    +nlink is 1, should be 0
     overwriting directory:
    +t_rename_overwrite: fstat(3): No such file or directory
    ...
    (Run 'diff -u tests/generic/035.out /home/jakob/code/fuse-xfstests/results//generic/035.out.bad'  to see the entire diff)
generic/036  [not run] src/aio-dio-regress/aio-dio-fcntl-race not built
generic/037  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/038  [not run] This test requires at least 10GB free on /tmp/check-gocryptfs/scratchdir to run
generic/039  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/040  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/041  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/042  [not run] fuse.gocryptfs does not support shutdown
generic/043  [not run] fuse.gocryptfs does not support shutdown
generic/044  [not run] fuse.gocryptfs does not support shutdown
generic/045  [not run] fuse.gocryptfs does not support shutdown
generic/046  [not run] fuse.gocryptfs does not support shutdown
generic/047  [not run] fuse.gocryptfs does not support shutdown
generic/048  [not run] fuse.gocryptfs does not support shutdown
generic/049  [not run] fuse.gocryptfs does not support shutdown
generic/050  [not run] fuse.gocryptfs does not support shutdown
generic/051  [not run] fuse.gocryptfs does not support shutdown
generic/052  [not run] fuse.gocryptfs does not support shutdown
generic/053  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/054  [not run] fuse.gocryptfs does not support shutdown
generic/055  [not run] fuse.gocryptfs does not support shutdown
generic/056  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/057  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/058  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/059  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/060  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/061  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/062  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/063  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/064  [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/065  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/066  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/067  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/068  [not run] fuse.gocryptfs does not support freezing
generic/069 173s ... - output mismatch (see /home/jakob/code/fuse-xfstests/results//generic/069.out.bad)
    --- tests/generic/069.out   2018-01-20 14:29:39.068451953 +0100
    +++ /home/jakob/code/fuse-xfstests/results//generic/069.out.bad 2018-01-21 20:10:58.615863085 +0100
    @@ -1,6 +1,8 @@
     QA output created by 069
     *** mkfs
     *** mount FS
    +2018/01/21 20:07:53 Unimplemented opcode INTERRUPT
    +2018/01/21 20:07:53 writer: Write/Writev failed, err: 2=no such file or directory. opcode: INTERRUPT
     *** checking file with 1 integers
     *** checking file with 20 integers
    ...
    (Run 'diff -u tests/generic/069.out /home/jakob/code/fuse-xfstests/results//generic/069.out.bad'  to see the entire diff)
generic/070  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/071 0s ... 1s
generic/072  [not run] xfs_io fcollapse failed (old kernel/wrong fs?)
generic/073  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/074 543s ... 335s
generic/075 4s ... 4s
generic/076  [not run] require /tmp/check-gocryptfs/scratchdev to be local device
generic/077  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/078  [not run] fs doesn't support RENAME_WHITEOUT
generic/079  [not run] file system doesn't support chattr +ia
generic/080 2s ... 2s
generic/081  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/082  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/083  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/084 6s ... - output mismatch (see /home/jakob/code/fuse-xfstests/results//generic/084.out.bad)
    --- tests/generic/084.out   2018-01-20 14:29:39.069451955 +0100
    +++ /home/jakob/code/fuse-xfstests/results//generic/084.out.bad 2018-01-21 20:16:49.354486067 +0100
    @@ -1,2 +1,4 @@
     QA output created by 084
     Silence is golden
    +2018/01/21 20:16:49 Unimplemented opcode INTERRUPT
    +2018/01/21 20:16:49 writer: Write/Writev failed, err: 2=no such file or directory. opcode: INTERRUPT
    ...
    (Run 'diff -u tests/generic/084.out /home/jakob/code/fuse-xfstests/results//generic/084.out.bad'  to see the entire diff)
generic/085  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/086 1s ... 1s
generic/087 0s ... 0s
generic/088 0s ... 1s
generic/089 36s ... 35s
generic/090  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/091  [not run] O_DIRECT is not supported
generic/092  [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/093  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/094  [not run] O_DIRECT is not supported
generic/095  [not run] O_DIRECT is not supported
generic/096  [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/097  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/098 0s ... 0s
generic/099  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/100 21s ... 17s
generic/101  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/102  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/103  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/104  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/105  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/106  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/107  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/108  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/109 2s ... 2s
generic/110  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/111  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/112  [not run] kernel does not support asynchronous I/O
generic/113  [not run] kernel does not support asynchronous I/O
generic/114  [not run] src/aio-dio-regress/aio-dio-eof-race not built
generic/115  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/116  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/117  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/118  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/119  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/120  [not run] atime related mount options have no effect on gocryptfs
generic/121  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/122  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/123 0s ... 0s
generic/124 5s ... 4s
generic/125  [not run] O_DIRECT is not supported
generic/126 0s ... 0s
generic/127 183s ... 168s
generic/128 0s ... 0s
generic/129 28s ... 25s
generic/130  [not run] O_DIRECT is not supported
generic/131 1s ... 1s
generic/132 37s ... 25s
generic/133  [not run] O_DIRECT is not supported
generic/134  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/135  [not run] O_DIRECT is not supported
generic/136  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/137  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/138  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/139  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/140  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/141 1s ... 0s
generic/142  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/143  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/144  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/145  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/146  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/147  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/148  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/149  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/150  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/151  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/152  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/153  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/154  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/155  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/156  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/157  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/158  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/159  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/160  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/161  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/162  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/163  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/164  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/165  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/166  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/167  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/168  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/169 0s ... 0s
generic/170  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/171  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/172  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/173  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/174  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/175  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/176  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/177  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/178  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/179  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/180  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/181  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/182  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/183  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/184 0s ... 0s
generic/185  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/186  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/187  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/188  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/189  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/190  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/191  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/192  [not run] atime related mount options have no effect on gocryptfs
generic/193 1s ... 1s
generic/194  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/195  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/196  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/197  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/198  [not run] src/aio-dio-regress/aiodio_sparse2 not built
generic/199  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/200  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/201  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/202  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/203  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/204  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/205  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/206  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/207  [not run] src/aio-dio-regress/aio-dio-extend-stat not built
generic/208  [not run] src/aio-dio-regress/aio-dio-invalidate-failure not built
generic/209  [not run] src/aio-dio-regress/aio-dio-invalidate-readahead not built
generic/210  [not run] src/aio-dio-regress/aio-dio-subblock-eof-read not built
generic/211  [not run] src/aio-dio-regress/aio-free-ring-with-bogus-nr-pages not built
generic/212  [not run] src/aio-dio-regress/aio-io-setup-with-nonwritable-context-pointer not built
generic/213 4s ... 4s
generic/214  [not run] O_DIRECT is not supported
generic/215 3s ... 2s
generic/216  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/217  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/218  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/219  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/220  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/221 1s ... 1s
generic/222  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/223  [not run] can't mkfs fuse.gocryptfs with geometry
generic/224  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/225  [not run] O_DIRECT is not supported
generic/226  [not run] O_DIRECT is not supported
generic/227  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/228  - output mismatch (see /home/jakob/code/fuse-xfstests/results//generic/228.out.bad)
    --- tests/generic/228.out   2018-01-20 14:29:39.087452003 +0100
    +++ /home/jakob/code/fuse-xfstests/results//generic/228.out.bad 2018-01-21 20:22:13.506043830 +0100
    @@ -1,6 +1,5 @@
     QA output created by 228
     File size limit is now set to 100 MB.
     Let us try to preallocate 101 MB. This should fail.
    -File size limit exceeded
     Let us now try to preallocate 50 MB. This should succeed.
     Test over.
    ...
    (Run 'diff -u tests/generic/228.out /home/jakob/code/fuse-xfstests/results//generic/228.out.bad'  to see the entire diff)
generic/229  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/230  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/231  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/232  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/233  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/234  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/235  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/236 1s ... 2s
generic/237  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/238  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/239  [not run] src/aio-dio-regress/aio-dio-hole-filling-race not built
generic/240  [not run] src/aio-dio-regress/aiodio_sparse2 not built
generic/241  72s
generic/242  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/243  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/244  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/245 1s ... 0s
generic/246 0s ... 0s
generic/247 14s ... 15s
generic/248 1s ... 0s
generic/249 1s ... 2s
generic/250  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/251  [not run] FITRIM not supported on /tmp/check-gocryptfs/scratchdir
generic/252  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/253  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/254  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/255  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/256  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/257 0s ... 1s
generic/258 1s ... 0s
generic/259  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/260  [not run] FITRIM not supported on /tmp/check-gocryptfs/scratchdir
generic/261  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/262  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/263  [not run] O_DIRECT is not supported
generic/264  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/265  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/266  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/267  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/268  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/269  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/270  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/271  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/272  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/273  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/274  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/275  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/276  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/277  [not run] file system doesn't support chattr +A
generic/278  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/279  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/280  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/281  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/282  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/283  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/284  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/285 0s ... 0s
generic/286 22s ... 17s
generic/287  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/288  [not run] FITRIM not supported on /tmp/check-gocryptfs/scratchdir
generic/289  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/290  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/291  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/292  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/293  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/294 0s ... 0s
generic/295  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/296  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/297  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/298  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/299  [not run] O_DIRECT is not supported
generic/300  [not run] O_DIRECT is not supported
generic/301  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/302  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/303  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/304  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/305  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/306 1s ... 0s
generic/307 1s ... 2s
generic/308 0s ... 0s
generic/309 2s ... 1s
generic/310 64s ... 67s
generic/311  [not run] O_DIRECT is not supported
generic/312  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/313 4s ... 4s
generic/314 0s ... 0s
generic/315 1s ... 0s
generic/316  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/317 0s ... 0s
generic/318  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/319  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/320  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/321  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/322  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/323  [not run] src/aio-dio-regress/aio-last-ref-held-by-io not built
generic/324  [not run] defragmentation not supported for fstype "fuse.gocryptfs"
generic/325  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/326  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/327  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/328  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/329  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/330  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/331  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/332  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/333  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/334  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/335  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/336  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/337  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/338  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/339 8s ... 7s
generic/340 14s ... 9s
generic/341  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/342  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/343  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/344 43s ... 34s
generic/345 27s ... 20s
generic/346 33s ... 26s
generic/347  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/348  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/349  [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/350  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/351  [not run] xfs_io finsert failed (old kernel/wrong fs?)
generic/352  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/353  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/354 9s ... 7s
generic/355  [not run] O_DIRECT is not supported
generic/356  [not run] swapfiles are not supported
generic/357  [not run] swapfiles are not supported
generic/358  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/359  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/360 0s ... 0s
generic/361  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/362  [not run] this test requires richacl support on $SCRATCH_DEV
generic/363  [not run] this test requires richacl support on $SCRATCH_DEV
generic/364  [not run] this test requires richacl support on $SCRATCH_DEV
generic/365  [not run] this test requires richacl support on $SCRATCH_DEV
generic/366  [not run] this test requires richacl support on $SCRATCH_DEV
generic/367  [not run] this test requires richacl support on $SCRATCH_DEV
generic/368  [not run] this test requires richacl support on $SCRATCH_DEV
generic/369  [not run] this test requires richacl support on $SCRATCH_DEV
generic/370  [not run] this test requires richacl support on $SCRATCH_DEV
generic/371  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/372  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/373  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/374  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/375  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/376  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/377  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/378 0s ... 0s
generic/379  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/380  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/381  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/382  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/383  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/384  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/385  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/386  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/387  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/388  [not run] fuse.gocryptfs does not support shutdown
generic/389  [not run] xfs_io flink failed (old kernel/wrong fs?)
generic/390  [not run] fuse.gocryptfs does not support freezing
generic/391  - output mismatch (see /home/jakob/code/fuse-xfstests/results//generic/391.out.bad)
    --- tests/generic/391.out   2018-01-20 14:29:39.105452050 +0100
    +++ /home/jakob/code/fuse-xfstests/results//generic/391.out.bad 2018-01-21 20:27:35.353597629 +0100
    @@ -1,2 +1,3 @@
     QA output created by 391
    +open: Invalid argument
     Silence is golden
    ...
    (Run 'diff -u tests/generic/391.out /home/jakob/code/fuse-xfstests/results//generic/391.out.bad'  to see the entire diff)
generic/392  [not run] fuse.gocryptfs does not support shutdown
generic/393 0s ... 1s
generic/394 0s ... 0s
generic/395  [not run] No encryption support for fuse.gocryptfs
generic/396  [not run] No encryption support for fuse.gocryptfs
generic/397  [not run] No encryption support for fuse.gocryptfs
generic/398  [not run] No encryption support for fuse.gocryptfs
generic/399  [not run] No encryption support for fuse.gocryptfs
generic/400  [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/401 1s ... 1s
generic/402  [not run] no kernel support for y2038 sysfs switch
generic/403  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/404  [not run] xfs_io finsert failed (old kernel/wrong fs?)
generic/405  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/406  [not run] O_DIRECT is not supported
generic/407  [not run] Reflink not supported by test filesystem type: fuse.gocryptfs
generic/408  [not run] Dedupe not supported by test filesystem type: fuse.gocryptfs
generic/409  [not run] require /tmp/check-gocryptfs/scratchdev to be local device
generic/410  [not run] require /tmp/check-gocryptfs/scratchdev to be local device
generic/411  [not run] require /tmp/check-gocryptfs/scratchdev to be local device
generic/412  [not run] O_DIRECT is not supported
generic/413  [not run] /tmp/check-gocryptfs/scratchdev fuse.gocryptfs does not support -o dax
generic/414  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/415  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/416  [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/417  [not run] fuse.gocryptfs does not support shutdown
generic/418  [not run] O_DIRECT is not supported
generic/419  [not run] No encryption support for fuse.gocryptfs
generic/420  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/421  [not run] No encryption support for fuse.gocryptfs
generic/422  [not run] O_DIRECT is not supported
generic/423 1s ... 0s
generic/424  [not run] file system doesn't support any of /bin/chattr +a/+c/+d/+i
generic/425  [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/426  - output mismatch (see /home/jakob/code/fuse-xfstests/results//generic/426.out.bad)
    --- tests/generic/426.out   2018-01-20 14:29:39.109452060 +0100
    +++ /home/jakob/code/fuse-xfstests/results//generic/426.out.bad 2018-01-21 20:27:45.410614934 +0100
    @@ -1,2 +1,3074 @@
     QA output created by 426
    +open_by_handle(0) returned 116 incorrectly on a linked file!
    +open_by_handle(1) returned 116 incorrectly on a linked file!
    +open_by_handle(2) returned 116 incorrectly on a linked file!
    +open_by_handle(3) returned 116 incorrectly on a linked file!
    +open_by_handle(4) returned 116 incorrectly on a linked file!
    +open_by_handle(5) returned 116 incorrectly on a linked file!
    ...
    (Run 'diff -u tests/generic/426.out /home/jakob/code/fuse-xfstests/results//generic/426.out.bad'  to see the entire diff)
generic/427  [not run] src/aio-dio-regress/aio-dio-eof-race not built
generic/428 0s ... 0s
generic/429  [not run] No encryption support for fuse.gocryptfs
generic/430 0s ... 0s
generic/431 1s ... 0s
generic/432 0s ... 1s
generic/433 0s ... 0s
generic/434 0s ... 0s
generic/435  [not run] No encryption support for fuse.gocryptfs
generic/436 0s ... 1s
generic/437 1s ... 1s
generic/438 26s ... 17s
generic/439  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/440  [not run] No encryption support for fuse.gocryptfs
generic/441  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/442  [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/443 0s ... 1s
generic/444  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/445 0s ... 0s
generic/446  [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/447  [not run] Reflink not supported by scratch filesystem type: fuse.gocryptfs
generic/448 0s ... 1s
generic/449  [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
shared/001   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/002   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/003   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/004   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/005   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/006   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/007   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/032   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/272   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/289   [not run] not suitable for this filesystem type: fuse.gocryptfs
shared/298   [not run] not suitable for this filesystem type: fuse.gocryptfs
Ran: generic/001 generic/002 generic/005 generic/006 generic/007 generic/011 generic/013 generic/014 generic/023 generic/028 generic/029 generic/030 generic/035 generic/069 generic/071 generic/074 generic/075 generic/080 generic/084 generic/086 generic/087 generic/088 generic/089 generic/098 generic/100 generic/109 generic/123 generic/124 generic/126 generic/127 generic/128 generic/129 generic/131 generic/132 generic/141 generic/169 generic/184 generic/193 generic/213 generic/215 generic/221 generic/228 generic/236 generic/241 generic/245 generic/246 generic/247 generic/248 generic/249 generic/257 generic/258 generic/285 generic/286 generic/294 generic/306 generic/307 generic/308 generic/309 generic/310 generic/313 generic/314 generic/315 generic/317 generic/339 generic/340 generic/344 generic/345 generic/346 generic/354 generic/360 generic/378 generic/391 generic/393 generic/394 generic/401 generic/423 generic/426 generic/428 generic/430 generic/431 generic/432 generic/433 generic/434 generic/436 generic/437 generic/438 generic/443 generic/445 generic/448
Not run: generic/003 generic/004 generic/008 generic/009 generic/010 generic/012 generic/015 generic/016 generic/017 generic/018 generic/019 generic/020 generic/021 generic/022 generic/024 generic/025 generic/026 generic/027 generic/031 generic/032 generic/033 generic/034 generic/036 generic/037 generic/038 generic/039 generic/040 generic/041 generic/042 generic/043 generic/044 generic/045 generic/046 generic/047 generic/048 generic/049 generic/050 generic/051 generic/052 generic/053 generic/054 generic/055 generic/056 generic/057 generic/058 generic/059 generic/060 generic/061 generic/062 generic/063 generic/064 generic/065 generic/066 generic/067 generic/068 generic/070 generic/072 generic/073 generic/076 generic/077 generic/078 generic/079 generic/081 generic/082 generic/083 generic/085 generic/090 generic/091 generic/092 generic/093 generic/094 generic/095 generic/096 generic/097 generic/099 generic/101 generic/102 generic/103 generic/104 generic/105 generic/106 generic/107 generic/108 generic/110 generic/111 generic/112 generic/113 generic/114 generic/115 generic/116 generic/117 generic/118 generic/119 generic/120 generic/121 generic/122 generic/125 generic/130 generic/133 generic/134 generic/135 generic/136 generic/137 generic/138 generic/139 generic/140 generic/142 generic/143 generic/144 generic/145 generic/146 generic/147 generic/148 generic/149 generic/150 generic/151 generic/152 generic/153 generic/154 generic/155 generic/156 generic/157 generic/158 generic/159 generic/160 generic/161 generic/162 generic/163 generic/164 generic/165 generic/166 generic/167 generic/168 generic/170 generic/171 generic/172 generic/173 generic/174 generic/175 generic/176 generic/177 generic/178 generic/179 generic/180 generic/181 generic/182 generic/183 generic/185 generic/186 generic/187 generic/188 generic/189 generic/190 generic/191 generic/192 generic/194 generic/195 generic/196 generic/197 generic/198 generic/199 generic/200 generic/201 generic/202 generic/203 generic/204 generic/205 generic/206 generic/207 generic/208 generic/209 generic/210 generic/211 generic/212 generic/214 generic/216 generic/217 generic/218 generic/219 generic/220 generic/222 generic/223 generic/224 generic/225 generic/226 generic/227 generic/229 generic/230 generic/231 generic/232 generic/233 generic/234 generic/235 generic/237 generic/238 generic/239 generic/240 generic/242 generic/243 generic/244 generic/250 generic/251 generic/252 generic/253 generic/254 generic/255 generic/256 generic/259 generic/260 generic/261 generic/262 generic/263 generic/264 generic/265 generic/266 generic/267 generic/268 generic/269 generic/270 generic/271 generic/272 generic/273 generic/274 generic/275 generic/276 generic/277 generic/278 generic/279 generic/280 generic/281 generic/282 generic/283 generic/284 generic/287 generic/288 generic/289 generic/290 generic/291 generic/292 generic/293 generic/295 generic/296 generic/297 generic/298 generic/299 generic/300 generic/301 generic/302 generic/303 generic/304 generic/305 generic/311 generic/312 generic/316 generic/318 generic/319 generic/320 generic/321 generic/322 generic/323 generic/324 generic/325 generic/326 generic/327 generic/328 generic/329 generic/330 generic/331 generic/332 generic/333 generic/334 generic/335 generic/336 generic/337 generic/338 generic/341 generic/342 generic/343 generic/347 generic/348 generic/349 generic/350 generic/351 generic/352 generic/353 generic/355 generic/356 generic/357 generic/358 generic/359 generic/361 generic/362 generic/363 generic/364 generic/365 generic/366 generic/367 generic/368 generic/369 generic/370 generic/371 generic/372 generic/373 generic/374 generic/375 generic/376 generic/377 generic/379 generic/380 generic/381 generic/382 generic/383 generic/384 generic/385 generic/386 generic/387 generic/388 generic/389 generic/390 generic/392 generic/395 generic/396 generic/397 generic/398 generic/399 generic/400 generic/402 generic/403 generic/404 generic/405 generic/406 generic/407 generic/408 generic/409 generic/410 generic/411 generic/412 generic/413 generic/414 generic/415 generic/416 generic/417 generic/418 generic/419 generic/420 generic/421 generic/422 generic/424 generic/425 generic/427 generic/429 generic/435 generic/439 generic/440 generic/441 generic/442 generic/444 generic/446 generic/447 generic/449 shared/001 shared/002 shared/003 shared/004 shared/005 shared/006 shared/007 shared/032 shared/272 shared/289 shared/298
Failures: generic/035 generic/069 generic/084 generic/228 generic/391 generic/426
Failed 6 of 89 tests
```
