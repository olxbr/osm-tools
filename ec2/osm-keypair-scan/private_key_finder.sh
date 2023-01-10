#!/bin/bash
filename="$1"
auth="<auth-key>"
api_url="<api-url>"

cmd() {
    fingerprint=$1
    echo $(curl -s -w "%{http_code}" -o /dev/null \
        -H "authorization: ${auth}" \
        -H "content-type: application/json" \
        -d "{\"fingerprint\": \"${fingerprint}\"}" \
        ${api_url}/ec2-check-keypair)
}

if [[ "$filename" =~ python[0-9.]+[\/test|\/site-packages] ||
    "$filename" =~ ruby\/gems\/[0-9]+\.[0-9]+\.[0-9]+ ||
    "$filename" =~ node_modules ||
    "$filename" =~ mnt/master-vol-[0-9a-f]+ ]]; then
    exit 0
fi

key=$(head -n 1 "$filename" | grep PRIVATE\ KEY 2>/dev/null);
if ! [ -n "$key" ]; then
    exit 0
fi

if command -v ssh-keygen &>/dev/null; then
    sha256=$(ssh-keygen -lf "$filename" 2>/dev/null | awk '{print $2}')
    if [ $(cmd ${sha256/* }) -eq "200" ]; then
        rm -f $filename
        exit 0
    fi
fi

if command -v openssl &>/dev/null; then
    sha1=$(openssl pkcs8 -in "$filename" -inform PEM -outform DER -topk8 -nocrypt 2>/dev/null| openssl sha1 -c)
    if [ $(cmd ${sha1/* }) -eq "200" ]; then
        rm -f $filename
        exit 0
    fi

    md5=$(openssl rsa -in "$filename" -pubout -outform DER 2>/dev/null | openssl md5 -c)
    if [ $(cmd ${md5/* }) -eq "200" ]; then
        rm -f $filename
        exit 0
    fi
fi

exit 0
