#!/bin/bash

# Function to handle cleanup
cleanup() {
    echo ""
    echo "🛑 Stopping simulation..."
    if [ ! -z "$SIM_PID" ]; then
        kill $SIM_PID 2>/dev/null
    fi
    exit
}

# Trap Ctrl+C
trap cleanup SIGINT

# 1. Start Traffic Simulator in background
echo -e "\033[1;32m🚀 Starting Traffic Simulator...\033[0m"
python3 scripts/simulate_traffic.py > /dev/null 2>&1 &
SIM_PID=$!

# 2. Open Browser (Try Zen Browser specific commands, fall back to xdg-open)
echo -e "\033[1;34m🌐 Opening Dashboard in Browser...\033[0m"
if command -v zen-browser &> /dev/null; then
    zen-browser http://localhost:8000 &
elif command -v zen &> /dev/null; then
    zen http://localhost:8000 &
else
    xdg-open http://localhost:8000 > /dev/null 2>&1 &
fi

# 3. Show the logs (This is what will be recorded by asciinema)
echo -e "\033[1;33m📡 Streaming Server Logs (Press Ctrl+C to stop recording)...\033[0m"
echo "----------------------------------------------------------------"
# Tail logs, filtering for the cool stuff
docker-compose logs -f --tail=0 tenebrinet

cleanup
