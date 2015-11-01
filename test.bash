#!/bin/bash

set -eux

for i in ./cryptfs .
do

	go build $i
	go test $i
done

