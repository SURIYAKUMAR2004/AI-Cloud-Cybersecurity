#!/bin/bash

echo "=============================================="
echo " AI CLOUD CYBERSECURITY - LIVE DEMO FEED"
echo "=============================================="
echo "Synthetic events → FastAPI → AI pipeline"
echo "Clearly labelled DEMO events"
echo

i=1

while true
do
    case $((i % 6)) in
        0)
            USER="demo_user"
            IP="10.10.10.20"
            ACTION="GetObject"
            STATUS="Success"
            BYTES=1200
            ;;
        1)
            USER="demo_user"
            IP="10.10.10.20"
            ACTION="ListBuckets"
            STATUS="Success"
            BYTES=800
            ;;
        2)
            USER="demo_user"
            IP="45.155.205.10"
            ACTION="AssumeRole"
            STATUS="Failed"
            BYTES=5000
            ;;
        3)
            USER="demo_user"
            IP="45.155.205.10"
            ACTION="ChangePassword"
            STATUS="Success"
            BYTES=12000
            ;;
        4)
            USER="demo_user"
            IP="45.155.205.10"
            ACTION="GetObject"
            STATUS="Success"
            BYTES=65000
            ;;
        5)
            USER="demo_user"
            IP="45.155.205.10"
            ACTION="DeleteObject"
            STATUS="Success"
            BYTES=90000
            ;;
    esac

    RESPONSE=$(curl -s -X POST http://localhost:8000/events \
      -H "Content-Type: application/json" \
      -d "{\"user\":\"$USER\",\"source_ip\":\"$IP\",\"action\":\"$ACTION\",\"status\":\"$STATUS\",\"bytes_transferred\":$BYTES}")

    echo "[DEMO LIVE] $ACTION | $STATUS | $IP | API response received"

    i=$((i+1))
    sleep 4
done
