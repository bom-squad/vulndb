#!/bin/bash

# This script forwards all arguments to the vulndb command

# Forwarding arguments
/etc/init.d/postgresql start
vulndb "$@"
