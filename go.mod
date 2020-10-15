module github.com/rfjakob/gocryptfs

go 1.13

require (
	github.com/hanwen/go-fuse/v2 v2.0.4-0.20200908172753-0b6cbc515082
	github.com/jacobsa/crypto v0.0.0-20190317225127-9f44e2d11115
	github.com/jacobsa/oglematchers v0.0.0-20150720000706-141901ea67cd // indirect
	github.com/jacobsa/oglemock v0.0.0-20150831005832-e94d794d06ff // indirect
	github.com/jacobsa/ogletest v0.0.0-20170503003838-80d50a735a11 // indirect
	github.com/jacobsa/reqtrace v0.0.0-20150505043853-245c9e0234cb // indirect
	github.com/pkg/xattr v0.4.1
	github.com/rfjakob/eme v1.1.1
	github.com/sabhiram/go-gitignore v0.0.0-20180611051255-d3107576ba94
	github.com/stretchr/testify v1.5.1 // indirect
	golang.org/x/crypto v0.0.0-20200429183012-4b2356b1ed79
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e // indirect
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	golang.org/x/sys v0.0.0-20200501145240-bc7a7d42d5c3
)

replace github.com/hanwen/go-fuse/v2 => github.com/rfjakob/go-fuse/v2 v2.0.4-0.20201015204057-88b12c99f8af
