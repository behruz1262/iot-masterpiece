#!/bin/bash

echo "📡 Starting IoT traffic capture..."
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
FILENAME="capture_${TIMESTAMP}.pcap"
FILEPATH="$HOME/iot_masterpiece/capture/$FILENAME"

echo "➡️  Capturing packets to: $FILENAME"
echo "👉 Turn on or interact with your IoT devices NOW..."
echo "⌛ Recording for 90 seconds..."

sudo tcpdump -i en0 -w "$FILEPATH" &
PID=$!
sleep 90
kill $PID

echo "✅ Done! File saved to: $FILEPATH"

