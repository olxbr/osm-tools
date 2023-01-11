#!/bin/bash
filename="$1"
auth="<auth-key>"
api_url="<api-url>"

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
fi

if command -v openssl &>/dev/null; then
    sha1=$(openssl pkcs8 -in "$filename" -inform PEM -outform DER -topk8 -nocrypt 2>/dev/null| openssl sha1 -c)
    md5=$(openssl rsa -in "$filename" -pubout -outform DER 2>/dev/null | openssl md5 -c)
fi

instance = $(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep '"instanceId"' | cut -d\" -f4)
account = $(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep '"accountId"' | cut -d\" -f4)

json_data='{
   "filename": "'"$filename"'",
   "fingerprint": {
       "sha256": "'"${sha256/* }"'",
       "sha1": "'"${sha1/* }"'",
       "md5": "'"${md5/* }"'"
    },
    "instance": "'"$instance"'",
    "account": "'"$account"'"
}'

status_code=$(curl -s -w "%{http_code}" -o /dev/null \
    -H "authorization: $auth" \
    -H "content-type: application/json" \
    -d "$json_data" \
    $api_url/ec2-check-keypair)

if [ $status_code -eq "200" ]; then
    rm -f $filename
    exit 0
fi

exit 0
