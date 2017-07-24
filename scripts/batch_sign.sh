#!/bin/sh

key=$1

sigfile=signature.txt

rm -f $sigfile

for f in *.luac ; do
    sign.sh $key $f >> $sigfile
done

cat $sigfile
