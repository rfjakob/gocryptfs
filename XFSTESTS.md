These are the results of running (fuse-xfstests)[https://github.com/rfjakob/fuse-xfstests]
against gocryptfs:

```
~/src/fuse-xfstests$ ./check-gocryptfs generic/???
FSTYP         -- fuse.gocryptfs
PLATFORM      -- Linux/x86_64 brikett 4.1.4-200.fc22.x86_64
MKFS_OPTIONS  -- /tmp/check-gocryptfs/scratchdev
MOUNT_OPTIONS -- -o context=system_u:object_r:nfs_t:s0 /tmp/check-gocryptfs/scratchdev /tmp/check-gocryptfs/scratchdir

generic/001 4s ... 5s
generic/002 0s ... 0s
generic/003	 [not run] atime related mount options have no effect on loopback file systems
generic/004	 [not run] xfs_io flink failed (old kernel/wrong fs?)
generic/005 0s ... 0s
generic/006 1s ... 2s
generic/007 3s ... 2s
generic/008	 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/009	 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/010 1s ... 2s
generic/011 2s ... 2s
generic/012	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/013 2s ... 0s
generic/014 37s ... 40s
generic/015	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/016	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/017	 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/018	 [not run] defragmentation not supported for fstype "fuse.gocryptfs"
generic/019	 [not run] Not running as root, skipping test
generic/020	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/021	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/022	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/023 1s ... 1s
generic/024	 [not run] fs doesn't support RENAME_NOREPLACE
generic/025	 [not run] fs doesn't support RENAME_EXCHANGE
generic/026	 [not run] Not running as root, skipping test
generic/027	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/028 5s ... 5s
generic/029 8s ... 0s
generic/030 9s ... 1s
generic/031	 [not run] xfs_io fcollapse failed (old kernel/wrong fs?)
generic/032	 [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/033	 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/034	 [not run] Not running as root, skipping test
generic/035	 - output mismatch (see /home/jakob/src/fuse-xfstests/results//generic/035.out.bad)
    --- tests/generic/035.out	2015-09-22 23:50:31.967720246 +0200
    +++ /home/jakob/src/fuse-xfstests/results//generic/035.out.bad	2015-10-07 22:16:46.625139272 +0200
    @@ -1,3 +1,4 @@
     QA output created by 035
     overwriting regular file:
     overwriting directory:
    +t_rename_overwrite: fstat(3): No such file or directory
    ...
    (Run 'diff -u tests/generic/035.out /home/jakob/src/fuse-xfstests/results//generic/035.out.bad'  to see the entire diff)
generic/036	 [not run] src/aio-dio-regress/aio-dio-fcntl-race not built
generic/037	 [not run] Not running as root, skipping test
generic/038	 [not run] Not running as root, skipping test
generic/039	 [not run] Not running as root, skipping test
generic/040	 [not run] Not running as root, skipping test
generic/041	 [not run] Not running as root, skipping test
generic/042	 [not run] fuse.gocryptfs does not support shutdown
generic/043	 [not run] fuse.gocryptfs does not support shutdown
generic/044	 [not run] fuse.gocryptfs does not support shutdown
generic/045	 [not run] fuse.gocryptfs does not support shutdown
generic/046	 [not run] fuse.gocryptfs does not support shutdown
generic/047	 [not run] fuse.gocryptfs does not support shutdown
generic/048	 [not run] fuse.gocryptfs does not support shutdown
generic/049	 [not run] fuse.gocryptfs does not support shutdown
generic/050	 [not run] fuse.gocryptfs does not support shutdown
generic/051	 [not run] fuse.gocryptfs does not support shutdown
generic/052	 [not run] fuse.gocryptfs does not support shutdown
generic/053 3s ... [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/054	 [not run] fuse.gocryptfs does not support shutdown
generic/055	 [not run] fuse.gocryptfs does not support shutdown
generic/056	 [not run] Not running as root, skipping test
generic/057	 [not run] Not running as root, skipping test
generic/058	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/059	 [not run] Not running as root, skipping test
generic/060	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/061	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/062	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/063	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/064	 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/065	 [not run] Not running as root, skipping test
generic/066	 [not run] Not running as root, skipping test
generic/067 5s ... [not run] fuse overlay filesystems do not support loopback devices
generic/068	 [not run] fuse.gocryptfs does not support freezing
generic/069 257s ... 298s
generic/070	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/071	 [not run] Not running as root, skipping test
generic/072	 [not run] xfs_io fcollapse failed (old kernel/wrong fs?)
generic/073	 [not run] Not running as root, skipping test
generic/074 677s ... 777s
generic/075 4s ... 5s
generic/076	 [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/077	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/078	 [not run] Not running as root, skipping test
generic/079	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/080 2s ... 2s
generic/081	 [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/082	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/083	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/084 8s ... 7s
generic/085	 [not run] require /tmp/check-gocryptfs/scratchdev to be valid block disk
generic/086 0s ... [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/087	 [not run] Not running as root, skipping test
generic/088	 [not run] Not running as root, skipping test
generic/089 30s ... 37s
generic/090	 [not run] Not running as root, skipping test
generic/091	 [not run] O_DIRECT is not supported
generic/092	 [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/093	 [not run] not suitable for this OS: Linux
generic/094	 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/095	 [not run] fio utility required, skipped this test
generic/096	 [not run] xfs_io fzero failed (old kernel/wrong fs?)
generic/097	 [not run] not suitable for this OS: Linux
generic/098	 [not run] Not running as root, skipping test
generic/099	 [not run] not suitable for this OS: Linux
generic/100 12s ... 15s
generic/101	 [not run] Not running as root, skipping test
generic/102	 [not run] Not running as root, skipping test
generic/103	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/104	 [not run] Not running as root, skipping test
generic/105	 [not run] Not running as root, skipping test
generic/106	 [not run] Not running as root, skipping test
generic/112	 [not run] fsx not built with AIO for this platform
generic/113	 [not run] aio-stress not built for this platform
generic/117	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/120	 [not run] atime related mount options have no effect on loopback file systems
generic/123	 [not run] fsgqa user not defined.
generic/124 9s ... 7s
generic/125	 [not run] fsgqa user not defined.
generic/126	 [not run] Not running as root, skipping test
generic/127 314s ... 359s
generic/128	 [not run] fsgqa user not defined.
generic/129 49s ... 59s
generic/130	 [not run] O_DIRECT is not supported
generic/131 1s ... 1s
generic/132 25s ... 23s
generic/133	 [not run] O_DIRECT is not supported
generic/135	 [not run] O_DIRECT is not supported
generic/141 2s ... 0s
generic/169 6s ... 1s
generic/184	 [not run] Not running as root, skipping test
generic/192	 [not run] atime related mount options have no effect on loopback file systems
generic/193	 [not run] fsgqa user not defined.
generic/198	 [not run] src/aio-dio-regress/aiodio_sparse2 not built
generic/204	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/207	 [not run] src/aio-dio-regress/aio-dio-extend-stat not built
generic/208	 [not run] src/aio-dio-regress/aio-dio-invalidate-failure not built
generic/209	 [not run] src/aio-dio-regress/aio-dio-invalidate-readahead not built
generic/210	 [not run] src/aio-dio-regress/aio-dio-subblock-eof-read not built
generic/211	 [not run] src/aio-dio-regress/aio-free-ring-with-bogus-nr-pages not built
generic/212	 [not run] src/aio-dio-regress/aio-io-setup-with-nonwritable-context-pointer not built
generic/213 1s ... [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/214 0s ... [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/215 3s ... 3s
generic/219	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/221 1s ... 1s
generic/223	 [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/224	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/225	 [not run] xfs_io fiemap failed (old kernel/wrong fs?)
generic/226	 [not run] O_DIRECT is not supported
generic/228	 [not run] FSIZE is not supported on FUSE
generic/230	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/231	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/232	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/233	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/234	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/235	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/236 2s ... 1s
generic/237	 [not run] Not running as root, skipping test
generic/239	 [not run] src/aio-dio-regress/aio-dio-hole-filling-race not built
generic/240	 [not run] src/aio-dio-regress/aiodio_sparse2 not built
generic/241 72s ... 72s
generic/245 0s ... 0s
generic/246 1s ... 1s
generic/247 25s ... 32s
generic/248 1s ... 0s
generic/249 4s ... 5s
generic/251	 [not run] FITRIM not supported on /tmp/check-gocryptfs/scratchdir
generic/255	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/256	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/257 1s ... 1s
generic/258 2s ... 0s
generic/260	 [not run] FITRIM not supported on /tmp/check-gocryptfs/scratchdir
generic/263	 [not run] O_DIRECT is not supported
generic/269	 [not run] Not running as root, skipping test
generic/270	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/273	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/274	 [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/275	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/277	 [not run] attrs not supported by this filesystem type: fuse.gocryptfs
generic/280	 [not run] disk quotas not supported by this filesystem type: fuse.gocryptfs
generic/285 0s ... 0s
generic/286 59s ... 39s
generic/288	 [not run] FITRIM not supported on /tmp/check-gocryptfs/scratchdir
generic/294	 [not run] Not running as root, skipping test
generic/299	 [not run] Not running as root, skipping test
generic/300	 [not run] Not running as root, skipping test
generic/306	 [not run] Not running as root, skipping test
generic/307 7s ... 1s
generic/308 0s ... 0s
generic/309 2s ... 1s
generic/310 64s ... 65s
generic/311	 [not run] Not running as root, skipping test
generic/312	 [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/313 2s ... 2s
generic/314	 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/315 1s ... [not run] xfs_io falloc failed (old kernel/wrong fs?)
generic/316	 [not run] xfs_io fpunch failed (old kernel/wrong fs?)
generic/317	 [not run] Not running as root, skipping test
generic/318	 [not run] Not running as root, skipping test
generic/319	 [not run] ACLs not supported by this filesystem type: fuse.gocryptfs
generic/320	 [not run] Filesystem fuse.gocryptfs not supported in _scratch_mkfs_sized
generic/321	 [not run] Not running as root, skipping test
generic/322	 [not run] Not running as root, skipping test
generic/323	 [not run] src/aio-dio-regress/aio-last-ref-held-by-io not built
generic/324	 [not run] Not running as root, skipping test
generic/325	 [not run] Not running as root, skipping test
Ran: generic/001 generic/002 generic/005 generic/006 generic/007 generic/010 generic/011 generic/013 generic/014 generic/023 generic/028 generic/029 generic/030 generic/035 generic/069 generic/074 generic/075 generic/080 generic/084 generic/089 generic/100 generic/124 generic/127 generic/129 generic/131 generic/132 generic/141 generic/169 generic/215 generic/221 generic/236 generic/241 generic/245 generic/246 generic/247 generic/248 generic/249 generic/257 generic/258 generic/285 generic/286 generic/307 generic/308 generic/309 generic/310 generic/313
Not run: generic/003 generic/004 generic/008 generic/009 generic/012 generic/015 generic/016 generic/017 generic/018 generic/019 generic/020 generic/021 generic/022 generic/024 generic/025 generic/026 generic/027 generic/031 generic/032 generic/033 generic/034 generic/036 generic/037 generic/038 generic/039 generic/040 generic/041 generic/042 generic/043 generic/044 generic/045 generic/046 generic/047 generic/048 generic/049 generic/050 generic/051 generic/052 generic/053 generic/054 generic/055 generic/056 generic/057 generic/058 generic/059 generic/060 generic/061 generic/062 generic/063 generic/064 generic/065 generic/066 generic/067 generic/068 generic/070 generic/071 generic/072 generic/073 generic/076 generic/077 generic/078 generic/079 generic/081 generic/082 generic/083 generic/085 generic/086 generic/087 generic/088 generic/090 generic/091 generic/092 generic/093 generic/094 generic/095 generic/096 generic/097 generic/098 generic/099 generic/101 generic/102 generic/103 generic/104 generic/105 generic/106 generic/112 generic/113 generic/117 generic/120 generic/123 generic/125 generic/126 generic/128 generic/130 generic/133 generic/135 generic/184 generic/192 generic/193 generic/198 generic/204 generic/207 generic/208 generic/209 generic/210 generic/211 generic/212 generic/213 generic/214 generic/219 generic/223 generic/224 generic/225 generic/226 generic/228 generic/230 generic/231 generic/232 generic/233 generic/234 generic/235 generic/237 generic/239 generic/240 generic/251 generic/255 generic/256 generic/260 generic/263 generic/269 generic/270 generic/273 generic/274 generic/275 generic/277 generic/280 generic/288 generic/294 generic/299 generic/300 generic/306 generic/311 generic/312 generic/314 generic/315 generic/316 generic/317 generic/318 generic/319 generic/320 generic/321 generic/322 generic/323 generic/324 generic/325
Failures: generic/035
Failed 1 of 46 tests
```
