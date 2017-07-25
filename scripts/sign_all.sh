#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 key_path" >&2
    exit 1
fi

key=$1
output=signature.txt

rm -f $output

find . -name "*.luac" -print0 | while IFS= read -r -d $'\0' line; do
    echo "signing $line"
    file=${line:2}
    openssl dgst -sha256 -sign $key -out $line.sha256 $line
    sig=`cat $line.sha256 | base64 | tr -d '\n'`
    echo "$sig  ${file}" >> $output
done

find . -name "*.sha256" -delete
