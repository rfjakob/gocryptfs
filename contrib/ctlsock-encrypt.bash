#!/bin/bash -eu
#
# Interactively encrypt file names and paths by querying a gocryptfs
# control socket.
#
# Dependencies:
#  Debian: apt-get install jq netcat-openbsd
#  Fedora: dnf install jq nmap-ncat
MYNAME=$(basename $0)
if [[ $# -ne 1 || $1 == "-h" ]] ; then
	echo "Usage: $MYNAME SOCKET"
	exit 1
fi
SOCK=$1
# Bail out early (before even prompting the user) if the socket does
# not exist
if [[ ! -S $SOCK ]] ; then
	echo "'$SOCK' is not a socket" >&2
	exit 1
fi
OPERATION=EncryptPath
if [[ $MYNAME == "ctlsock-decrypt.bash" ]] ; then
	OPERATION=DecryptPath
fi
while true ; do
	echo -n "Input path      : "
	read IN
	echo -n "Transformed path: "
	JSON=$(echo "{\"$OPERATION\":\"$IN\"}" | nc -U $SOCK)
	ENCRYPTED=$(echo $JSON | jq -r '.Result')
	echo $ENCRYPTED
	echo    "Complete reply  : $JSON"
	echo
done
