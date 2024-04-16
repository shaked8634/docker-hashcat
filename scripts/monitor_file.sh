#!/usr/bin/env bash

NTFY_TOPIC="TOPIC"
if [ -z "$1" ]; then
  echo "Usage: $0 <file>"
  exit 1
fi

FILE="$1"
echo Monitoring: "$FILE"


last_line=$(wc -l < "$FILE")

while true; do
    current_line=$(wc -l < "$FILE")
    if [ "$current_line" -ne "$last_line" ]; then
        tail -n $((current_line - last_line)) "$FILE"
        last_line=$current_line
         curl -q -H "Title: Hashcat" -d "Found hash:$current_line" "https://ntfy.sh/$NTFY_TOPIC"
    fi
    sleep 5
done