Go 1.4.2
========

39MB/s @1k

	go1.4/src/crypto/cipher$ go test -bench=.

	BenchmarkAESGCMSeal1K   	   50000	     25968 ns/op	  39.43 MB/s
	BenchmarkAESGCMOpen1K   	   50000	     25914 ns/op	  39.51 MB/s
	[...]

Go 1.5
======

41MB/s @1k

	go1.5/src/crypto/cipher$ ~/go/src/go1.5/bin/go test -bench=.

	BenchmarkAESGCMSeal1K-2   	   50000	     24429 ns/op	  41.92 MB/s
	BenchmarkAESGCMOpen1K-2   	   50000	     24578 ns/op	  41.66 MB/s
	BenchmarkAESGCMSeal8K-2   	   10000	    190340 ns/op	  43.04 MB/s
	BenchmarkAESGCMOpen8K-2   	   10000	    190308 ns/op	  43.05 MB/s
	[...]

openssl 1.0.1k
==============

302MB/s @1k

	$ openssl speed -elapsed -evp aes-128-gcm

	[...]
	The 'numbers' are in 1000s of bytes per second processed.
	type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes
	aes-128-gcm      71275.15k    80063.19k   275048.36k   302066.69k   308912.13k


gocryptfs with openssl bindings
===============================

148MB/s @4k

	gocryptfs/openssl_benchmark$ ./openssl_benchmark.bash 

	BenchmarkAESGCMSeal4K   	   20000	     98671 ns/op	  41.51 MB/s
	BenchmarkAESGCMOpen4K   	   20000	     98679 ns/op	  41.51 MB/s
	BenchmarkOpensslGCMenc4K	   50000	     27542 ns/op	 148.72 MB/s
	BenchmarkOpensslGCMdec4K	   50000	     27564 ns/op	 148.60 MB/s


CPU Info
========

This is tested on a dual-core Intel Sandy Bridge Pentium G630 which does NOT have
aes instructions ( https://en.wikipedia.org/wiki/AES_instruction_set )

	$ cat /proc/cpuinfo | fold -s -w 80

	processor	: 0
	vendor_id	: GenuineIntel
	cpu family	: 6
	model		: 42
	model name	: Intel(R) Pentium(R) CPU G630 @ 2.70GHz
	stepping	: 7
	microcode	: 0x29
	cpu MHz		: 1617.574
	cache size	: 3072 KB
	physical id	: 0
	siblings	: 2
	core id		: 0
	cpu cores	: 2
	apicid		: 0
	initial apicid	: 0
	fpu		: yes
	fpu_exception	: yes
	cpuid level	: 13
	wp		: yes
	flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov 
	pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx rdtscp lm 
	constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc 
	aperfmperf eagerfpu pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 cx16 
	xtpr pdcm pcid sse4_1 sse4_2 popcnt tsc_deadline_timer xsave lahf_lm arat epb 
	pln pts dtherm tpr_shadow vnmi flexpriority ept vpid xsaveopt
	bugs		:
	bogomips	: 5387.68
	clflush size	: 64
	cache_alignment	: 64
	address sizes	: 36 bits physical, 48 bits virtual
	power management:
	
	[...]
