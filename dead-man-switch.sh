#!/bin/bash
# Author: ablil
# Description: Dead man switch 

##################### usage #############################################
# create a cron job that reset the DEADMANSWITCH variable to 1 (ON state)
# create another cron job that run this script periodically
#   on your desired directory or files
# 
# As a user you need to periodically set DEADMANSWITCH to 0 (OFF State)
#   or the script will be triggered, and all data will be encrypted
#
# Note: the $keyid variable is the reference id of the gpg key to use for
#   encryption
#########################################################################

set -o errexit
set -o nounset
set -o pipefail
keyid=BBEC500B392905505E245A9726EE109272949F6F

############ SETUP STAGE ##################

# check args
[[ $# -eq 0 ]] && {
    echo "No file or directory is passed as an argument";
    echo "Usage: $0 file1 file2 dir1/ dir2 ...";
    exit 1;
} || {
    filenotfound=0

    for f in $@; do
        if [[ ! -d $f && ! -f $f ]]; then
            filenotfound=1;
            echo "$f NOT FOUND";
        fi
    done

    [[ $filenotfound -eq 1 ]] && exit 4;
}


################### ENCRYPTION STAGE ######################
function encrypt_file() {
    gpg --trust-model always --encrypt -r $keyid $1 && {
        shred -zu $1;
    }
}
if [[ ! -v DEADMANSWITCH ]] || [[ ! $DEADMANSWITCH -eq 0 ]]; then
    
    for f in $@; do

        if [[ -f $f ]]; then
            echo "Encrypting $f";
            encrypt_file $f
        fi

        if [[ -d $f ]]; then
            echo "encrypting directory $f";

            subfiles=$(find $f -type f)
            for subfile in $subfiles; do
                encrypt_file $subfile;
            done
        fi
    done
fi
