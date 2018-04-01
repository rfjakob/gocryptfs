#!/bin/bash
exec ../../gocryptfs -fsck -extpass "echo test" broken_fs_v1.4
