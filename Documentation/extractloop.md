# extractloop.bash results

What the extractloop stress test does is (top comment in `extractloop.bash`):

```
# Mount a gocryptfs filesystem somewhere on /tmp, then run two parallel
# infinite loops inside that do the following:
# 1) Extract linux-3.0.tar.gz
# 2) Verify the md5sums
# 3) Delete, go to (1)
#
# This test is good at discovering inode-related memory leaks because it creates
# huge numbers of files.
```

Memory usage stabilises at 119MiB, we do not run out of fds,
and the iteration time is stable at 37 seconds. The test
runs slower in the beginning due to xfstests running in
parallel on the test machine.

Test output (somewhat trimmed for brevity):

```
0 jakob@brikett:~/go/src/github.com/rfjakob/gocryptfs/tests/stress_tests$ date
Sun Jan 21 19:48:34 CET 2018
0 jakob@brikett:~/go/src/github.com/rfjakob/gocryptfs/tests/stress_tests$ gocryptfs -version
gocryptfs v1.4.2-71-gf63ce35; go-fuse v20170619-24-g3d30ad6; 2018-01-20 go1.9.2
0 jakob@brikett:~/go/src/github.com/rfjakob/gocryptfs/tests/stress_tests$ ./extractloop.bash 
Testing gocryptfs
Test dir: /tmp/extractloop.bash.yp3
[pid 23842] Starting loop
[pid 23843] Starting loop
[pid 23843] Iteration 1 done, 64 seconds, RSS 126268 kiB
[pid 23842] Iteration 1 done, 64 seconds, RSS 126268 kiB
[pid 23842] Iteration 2 done, 61 seconds, RSS 128512 kiB
[pid 23843] Iteration 2 done, 62 seconds, RSS 128512 kiB
[pid 23843] Iteration 3 done, 62 seconds, RSS 135564 kiB
[pid 23842] Iteration 3 done, 63 seconds, RSS 135564 kiB
[pid 23843] Iteration 4 done, 61 seconds, RSS 135564 kiB
[pid 23842] Iteration 4 done, 63 seconds, RSS 135564 kiB
[pid 23843] Iteration 5 done, 63 seconds, RSS 148592 kiB
[pid 23842] Iteration 5 done, 62 seconds, RSS 148592 kiB
[pid 23843] Iteration 6 done, 61 seconds, RSS 148592 kiB
[pid 23842] Iteration 6 done, 62 seconds, RSS 148592 kiB
[pid 23843] Iteration 7 done, 62 seconds, RSS 148592 kiB
[pid 23842] Iteration 7 done, 64 seconds, RSS 148592 kiB
[pid 23843] Iteration 8 done, 64 seconds, RSS 155412 kiB
[pid 23842] Iteration 8 done, 65 seconds, RSS 155412 kiB
[pid 23843] Iteration 9 done, 67 seconds, RSS 155412 kiB
[pid 23842] Iteration 9 done, 67 seconds, RSS 155412 kiB
[pid 23843] Iteration 10 done, 66 seconds, RSS 155412 kiB
[pid 23842] Iteration 10 done, 65 seconds, RSS 155412 kiB
[pid 23843] Iteration 11 done, 64 seconds, RSS 155412 kiB
[pid 23842] Iteration 11 done, 64 seconds, RSS 155412 kiB
[pid 23843] Iteration 12 done, 62 seconds, RSS 155412 kiB
[pid 23842] Iteration 12 done, 64 seconds, RSS 155412 kiB
[pid 23843] Iteration 13 done, 66 seconds, RSS 155412 kiB
[pid 23842] Iteration 13 done, 67 seconds, RSS 155412 kiB
[pid 23843] Iteration 14 done, 63 seconds, RSS 155412 kiB
[pid 23842] Iteration 14 done, 63 seconds, RSS 155412 kiB
[pid 23842] Iteration 15 done, 60 seconds, RSS 161136 kiB
[pid 23843] Iteration 15 done, 67 seconds, RSS 161136 kiB
[pid 23842] Iteration 16 done, 63 seconds, RSS 161136 kiB
[pid 23843] Iteration 16 done, 64 seconds, RSS 161136 kiB
[pid 23842] Iteration 17 done, 62 seconds, RSS 161136 kiB
[pid 23843] Iteration 17 done, 62 seconds, RSS 161136 kiB
[pid 23843] Iteration 18 done, 61 seconds, RSS 161136 kiB
[pid 23842] Iteration 18 done, 63 seconds, RSS 161136 kiB
[pid 23843] Iteration 19 done, 62 seconds, RSS 161136 kiB
[pid 23842] Iteration 19 done, 63 seconds, RSS 161136 kiB
[pid 23842] Iteration 20 done, 64 seconds, RSS 161136 kiB
[pid 23843] Iteration 20 done, 68 seconds, RSS 161136 kiB
[pid 23842] Iteration 21 done, 41 seconds, RSS 161136 kiB
[pid 23843] Iteration 21 done, 39 seconds, RSS 161136 kiB
[pid 23842] Iteration 22 done, 36 seconds, RSS 161380 kiB
[pid 23843] Iteration 22 done, 37 seconds, RSS 161380 kiB
[pid 23842] Iteration 23 done, 36 seconds, RSS 161380 kiB
[pid 23843] Iteration 23 done, 37 seconds, RSS 161380 kiB
[pid 23842] Iteration 24 done, 36 seconds, RSS 161380 kiB
[pid 23843] Iteration 24 done, 36 seconds, RSS 161380 kiB
[pid 23842] Iteration 25 done, 36 seconds, RSS 161628 kiB
[pid 23843] Iteration 25 done, 37 seconds, RSS 161628 kiB
[pid 23842] Iteration 26 done, 36 seconds, RSS 161628 kiB
[pid 23843] Iteration 26 done, 36 seconds, RSS 161628 kiB
[pid 23842] Iteration 27 done, 36 seconds, RSS 141060 kiB
[pid 23843] Iteration 27 done, 37 seconds, RSS 141060 kiB
[pid 23842] Iteration 28 done, 36 seconds, RSS 141060 kiB
[pid 23843] Iteration 28 done, 36 seconds, RSS 141060 kiB
[pid 23842] Iteration 29 done, 35 seconds, RSS 141060 kiB
[pid 23843] Iteration 29 done, 36 seconds, RSS 141060 kiB
[pid 23842] Iteration 30 done, 36 seconds, RSS 141060 kiB
[pid 23843] Iteration 30 done, 37 seconds, RSS 141320 kiB
[pid 23842] Iteration 31 done, 35 seconds, RSS 141320 kiB
[pid 23843] Iteration 31 done, 36 seconds, RSS 141320 kiB
[pid 23842] Iteration 32 done, 36 seconds, RSS 141320 kiB
[pid 23843] Iteration 32 done, 37 seconds, RSS 141320 kiB
[pid 23842] Iteration 33 done, 36 seconds, RSS 141320 kiB
[pid 23843] Iteration 33 done, 36 seconds, RSS 141320 kiB
[pid 23842] Iteration 34 done, 35 seconds, RSS 141320 kiB
[pid 23843] Iteration 34 done, 37 seconds, RSS 141320 kiB
[pid 23842] Iteration 35 done, 36 seconds, RSS 141320 kiB
[pid 23843] Iteration 35 done, 36 seconds, RSS 141320 kiB
[pid 23842] Iteration 36 done, 35 seconds, RSS 141320 kiB
[pid 23843] Iteration 36 done, 37 seconds, RSS 141320 kiB
[pid 23842] Iteration 37 done, 36 seconds, RSS 141320 kiB
[pid 23843] Iteration 37 done, 37 seconds, RSS 141320 kiB
[pid 23842] Iteration 38 done, 36 seconds, RSS 141320 kiB
[pid 23843] Iteration 38 done, 36 seconds, RSS 141320 kiB
[pid 23842] Iteration 39 done, 35 seconds, RSS 129656 kiB
[pid 23843] Iteration 39 done, 36 seconds, RSS 129656 kiB
[pid 23842] Iteration 40 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 40 done, 37 seconds, RSS 129656 kiB
[pid 23842] Iteration 41 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 41 done, 36 seconds, RSS 129656 kiB
[pid 23842] Iteration 42 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 42 done, 36 seconds, RSS 129656 kiB
[pid 23842] Iteration 43 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 43 done, 37 seconds, RSS 129656 kiB
[pid 23842] Iteration 44 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 44 done, 36 seconds, RSS 129656 kiB
[pid 23842] Iteration 45 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 45 done, 36 seconds, RSS 129656 kiB
[pid 23842] Iteration 46 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 46 done, 36 seconds, RSS 129656 kiB
[pid 23842] Iteration 47 done, 36 seconds, RSS 129656 kiB
[pid 23843] Iteration 47 done, 37 seconds, RSS 126576 kiB
[pid 23842] Iteration 48 done, 36 seconds, RSS 126576 kiB
[pid 23843] Iteration 48 done, 36 seconds, RSS 126820 kiB
[pid 23842] Iteration 49 done, 36 seconds, RSS 126820 kiB
[pid 23843] Iteration 49 done, 36 seconds, RSS 126820 kiB
[pid 23842] Iteration 50 done, 37 seconds, RSS 126820 kiB
[pid 23843] Iteration 50 done, 37 seconds, RSS 126820 kiB
[pid 23842] Iteration 51 done, 36 seconds, RSS 126820 kiB
[pid 23843] Iteration 51 done, 36 seconds, RSS 124156 kiB
[pid 23842] Iteration 52 done, 36 seconds, RSS 124156 kiB
[pid 23843] Iteration 52 done, 36 seconds, RSS 124156 kiB
[pid 23842] Iteration 53 done, 36 seconds, RSS 124156 kiB
[pid 23843] Iteration 53 done, 37 seconds, RSS 124156 kiB
[pid 23842] Iteration 54 done, 37 seconds, RSS 124156 kiB
[pid 23843] Iteration 54 done, 36 seconds, RSS 124156 kiB
[pid 23842] Iteration 55 done, 36 seconds, RSS 124156 kiB
[pid 23843] Iteration 55 done, 36 seconds, RSS 124156 kiB
[pid 23842] Iteration 56 done, 36 seconds, RSS 122004 kiB
[pid 23843] Iteration 56 done, 37 seconds, RSS 122004 kiB
[pid 23842] Iteration 57 done, 36 seconds, RSS 122004 kiB
[pid 23843] Iteration 57 done, 36 seconds, RSS 122004 kiB
[pid 23842] Iteration 58 done, 36 seconds, RSS 122004 kiB
[pid 23843] Iteration 58 done, 36 seconds, RSS 122004 kiB
[pid 23842] Iteration 59 done, 36 seconds, RSS 122004 kiB
[pid 23843] Iteration 59 done, 37 seconds, RSS 122004 kiB
[pid 23842] Iteration 60 done, 36 seconds, RSS 120636 kiB
[pid 23843] Iteration 60 done, 36 seconds, RSS 120636 kiB
[pid 23842] Iteration 61 done, 37 seconds, RSS 120636 kiB
[pid 23843] Iteration 61 done, 36 seconds, RSS 120636 kiB
[pid 23842] Iteration 62 done, 36 seconds, RSS 120636 kiB
[pid 23843] Iteration 62 done, 36 seconds, RSS 120636 kiB
[pid 23842] Iteration 63 done, 36 seconds, RSS 120636 kiB
[pid 23843] Iteration 63 done, 36 seconds, RSS 120636 kiB
[pid 23842] Iteration 64 done, 37 seconds, RSS 120116 kiB
[pid 23843] Iteration 64 done, 37 seconds, RSS 120116 kiB
[pid 23842] Iteration 65 done, 36 seconds, RSS 120116 kiB
[pid 23843] Iteration 65 done, 36 seconds, RSS 120116 kiB
[pid 23842] Iteration 66 done, 36 seconds, RSS 120116 kiB
[pid 23843] Iteration 66 done, 36 seconds, RSS 120116 kiB
[pid 23842] Iteration 67 done, 36 seconds, RSS 120116 kiB
[pid 23843] Iteration 67 done, 36 seconds, RSS 120116 kiB
[pid 23842] Iteration 68 done, 37 seconds, RSS 120100 kiB
[pid 23843] Iteration 68 done, 36 seconds, RSS 120100 kiB
[pid 23842] Iteration 69 done, 36 seconds, RSS 120100 kiB
[pid 23843] Iteration 69 done, 36 seconds, RSS 120100 kiB
[pid 23842] Iteration 70 done, 36 seconds, RSS 120100 kiB
[pid 23843] Iteration 70 done, 37 seconds, RSS 120100 kiB
[pid 23842] Iteration 71 done, 36 seconds, RSS 120100 kiB
[pid 23843] Iteration 71 done, 36 seconds, RSS 120100 kiB
[pid 23842] Iteration 72 done, 37 seconds, RSS 120100 kiB
[pid 23843] Iteration 72 done, 36 seconds, RSS 118964 kiB
[pid 23842] Iteration 73 done, 36 seconds, RSS 118964 kiB
[pid 23843] Iteration 73 done, 37 seconds, RSS 118964 kiB
[pid 23842] Iteration 74 done, 36 seconds, RSS 118964 kiB
[pid 23843] Iteration 74 done, 36 seconds, RSS 118964 kiB
[pid 23842] Iteration 75 done, 36 seconds, RSS 118964 kiB
[pid 23843] Iteration 75 done, 36 seconds, RSS 118964 kiB
[pid 23842] Iteration 76 done, 36 seconds, RSS 118964 kiB
[pid 23843] Iteration 76 done, 36 seconds, RSS 118956 kiB
[pid 23842] Iteration 77 done, 36 seconds, RSS 118956 kiB
[pid 23843] Iteration 77 done, 37 seconds, RSS 118956 kiB
[pid 23842] Iteration 78 done, 37 seconds, RSS 118956 kiB
[pid 23843] Iteration 78 done, 36 seconds, RSS 118956 kiB
[pid 23842] Iteration 79 done, 36 seconds, RSS 118956 kiB
[pid 23843] Iteration 79 done, 36 seconds, RSS 118956 kiB
[pid 23842] Iteration 80 done, 36 seconds, RSS 118956 kiB
[pid 23843] Iteration 80 done, 37 seconds, RSS 118812 kiB
[pid 23842] Iteration 81 done, 36 seconds, RSS 118812 kiB
[pid 23843] Iteration 81 done, 36 seconds, RSS 118812 kiB
[pid 23842] Iteration 82 done, 37 seconds, RSS 118812 kiB
[pid 23843] Iteration 82 done, 36 seconds, RSS 118812 kiB
[pid 23842] Iteration 83 done, 36 seconds, RSS 118812 kiB
[pid 23843] Iteration 83 done, 36 seconds, RSS 119068 kiB
[pid 23842] Iteration 84 done, 36 seconds, RSS 119068 kiB
[pid 23843] Iteration 84 done, 37 seconds, RSS 119044 kiB
[pid 23842] Iteration 85 done, 37 seconds, RSS 119044 kiB
[pid 23843] Iteration 85 done, 36 seconds, RSS 119044 kiB
[pid 23842] Iteration 86 done, 36 seconds, RSS 119044 kiB
[pid 23843] Iteration 86 done, 36 seconds, RSS 119044 kiB
[pid 23842] Iteration 87 done, 36 seconds, RSS 119044 kiB
[pid 23843] Iteration 87 done, 36 seconds, RSS 119044 kiB
[pid 23842] Iteration 88 done, 36 seconds, RSS 119044 kiB
[pid 23843] Iteration 88 done, 37 seconds, RSS 119044 kiB
[pid 23842] Iteration 89 done, 37 seconds, RSS 119012 kiB
[pid 23843] Iteration 89 done, 36 seconds, RSS 119012 kiB
[pid 23842] Iteration 90 done, 36 seconds, RSS 119788 kiB
[pid 23843] Iteration 90 done, 36 seconds, RSS 119788 kiB
[pid 23842] Iteration 91 done, 36 seconds, RSS 119788 kiB
[pid 23843] Iteration 91 done, 36 seconds, RSS 119788 kiB
[pid 23842] Iteration 92 done, 36 seconds, RSS 119788 kiB
[pid 23843] Iteration 92 done, 36 seconds, RSS 119788 kiB
[pid 23842] Iteration 93 done, 36 seconds, RSS 119788 kiB
[pid 23843] Iteration 93 done, 37 seconds, RSS 119788 kiB
[pid 23842] Iteration 94 done, 37 seconds, RSS 119788 kiB
[pid 23843] Iteration 94 done, 36 seconds, RSS 119788 kiB
[pid 23842] Iteration 95 done, 36 seconds, RSS 119788 kiB
[pid 23843] Iteration 95 done, 36 seconds, RSS 119788 kiB
[pid 23842] Iteration 96 done, 36 seconds, RSS 119788 kiB
[pid 23843] Iteration 96 done, 36 seconds, RSS 120052 kiB
[pid 23842] Iteration 97 done, 37 seconds, RSS 120052 kiB
[pid 23843] Iteration 97 done, 37 seconds, RSS 120052 kiB
[pid 23842] Iteration 98 done, 36 seconds, RSS 120052 kiB
[pid 23843] Iteration 98 done, 36 seconds, RSS 120052 kiB
[pid 23842] Iteration 99 done, 36 seconds, RSS 120052 kiB
[pid 23843] Iteration 99 done, 36 seconds, RSS 120052 kiB
[pid 23842] Iteration 100 done, 36 seconds, RSS 120052 kiB
[pid 23843] Iteration 100 done, 36 seconds, RSS 120052 kiB
[pid 23842] Iteration 101 done, 36 seconds, RSS 120052 kiB
[pid 23843] Iteration 101 done, 36 seconds, RSS 120036 kiB
[pid 23842] Iteration 102 done, 37 seconds, RSS 120036 kiB
[pid 23843] Iteration 102 done, 37 seconds, RSS 120036 kiB
[pid 23842] Iteration 103 done, 36 seconds, RSS 120036 kiB
[pid 23843] Iteration 103 done, 36 seconds, RSS 120036 kiB
[pid 23842] Iteration 104 done, 37 seconds, RSS 120036 kiB
[pid 23843] Iteration 104 done, 36 seconds, RSS 120036 kiB
[pid 23842] Iteration 105 done, 36 seconds, RSS 120036 kiB
[pid 23843] Iteration 105 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 106 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 106 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 107 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 107 done, 37 seconds, RSS 119420 kiB
[pid 23842] Iteration 108 done, 37 seconds, RSS 119420 kiB
[pid 23843] Iteration 108 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 109 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 109 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 110 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 110 done, 37 seconds, RSS 119420 kiB
[pid 23842] Iteration 111 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 111 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 112 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 112 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 113 done, 37 seconds, RSS 119420 kiB
[pid 23843] Iteration 113 done, 37 seconds, RSS 119420 kiB
[pid 23842] Iteration 114 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 114 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 115 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 115 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 116 done, 37 seconds, RSS 119420 kiB
[pid 23843] Iteration 116 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 117 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 117 done, 37 seconds, RSS 119420 kiB
[pid 23842] Iteration 118 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 118 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 119 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 119 done, 36 seconds, RSS 119420 kiB
[pid 23842] Iteration 120 done, 36 seconds, RSS 119420 kiB
[pid 23843] Iteration 120 done, 36 seconds, RSS 119668 kiB
[pid 23842] Iteration 121 done, 37 seconds, RSS 119668 kiB
[pid 23843] Iteration 121 done, 37 seconds, RSS 119668 kiB
[pid 23842] Iteration 122 done, 36 seconds, RSS 119668 kiB
[...]
[pid 23842] Iteration 1988 done, 36 seconds, RSS 119880 kiB
[pid 23843] Iteration 1988 done, 37 seconds, RSS 119880 kiB
[pid 23842] Iteration 1989 done, 36 seconds, RSS 119880 kiB
[pid 23843] Iteration 1989 done, 36 seconds, RSS 119880 kiB
[pid 23842] Iteration 1990 done, 36 seconds, RSS 119880 kiB
[pid 23843] Iteration 1990 done, 36 seconds, RSS 119880 kiB
[pid 23842] Iteration 1991 done, 36 seconds, RSS 119880 kiB
[pid 23843] Iteration 1991 done, 36 seconds, RSS 119880 kiB
[pid 23842] Iteration 1992 done, 37 seconds, RSS 119728 kiB
[pid 23843] Iteration 1992 done, 36 seconds, RSS 119728 kiB
[pid 23842] Iteration 1993 done, 36 seconds, RSS 119728 kiB
[pid 23843] Iteration 1993 done, 37 seconds, RSS 119728 kiB
[pid 23842] Iteration 1994 done, 36 seconds, RSS 119728 kiB
[pid 23843] Iteration 1994 done, 37 seconds, RSS 119728 kiB
^C2018/01/21 12:00:43 Unimplemented opcode INTERRUPT

130 jakob@brikett:~/go/src/github.com/rfjakob/gocryptfs/tests/stress_tests$
```
