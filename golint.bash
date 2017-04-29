#!/bin/bash

golint ./... | \
 grep -v "don't use an underscore in package name" | \
 grep -v "don't use ALL_CAPS in Go names; use CamelCase" |
 grep -v "struct field allow_other should be allowOther" |
 grep -v "struct field serialize_reads should be serializeReads"
