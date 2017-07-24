#!/bin/bash

tmpfile=/tmp/tmp.sha256
#echo "sign signature for $2 by use key $1"
[ -f $1 ] && openssl dgst -sha256 -sign $1 -out /tmp/tmp.sha256 $2
sig=`cat $tmpfile | base64 | tr -d '\n'`
echo "$sig    $2"

