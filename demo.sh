#!/bin/bash

# Port Scanner Demo Script
# Made with love by n0vember

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗  ║"
echo "║  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ ║"
echo "║  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ ║"
echo "║  ██╔══██╗██║   ██║██╔═══╝    ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗ ║"
echo "║  ██║  ██║╚██████╔╝██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ ║"
echo "║  ╚═╝  ╚═╝ ╚═════╝ ╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ║"
echo "║                                                              ║"
echo "║                    FAST & POWERFUL PORT SCANNER                    ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Made with love by n0vember"
echo "Port Scanner Demo - Showcasing Features"
echo ""

# Check if port scanner is available
if ! command -v python3 port_scanner.py &> /dev/null && [ ! -f "./port_scanner.py" ]; then
    echo "❌ Port scanner not found. Please run the installation script first."
    exit 1
fi

# Function to run scanner with delay
run_demo() {
    local title="$1"
    local command="$2"
    
    echo "🔍 $title"
    echo "Command: $command"
    echo "─" * 50
    eval "$command"
    echo ""
    echo "Press Enter to continue to next demo..."
    read -r
    echo ""
}

echo "🚀 Starting Port Scanner Demo"
echo "This demo will showcase various scanning techniques."
echo ""

# Demo 1: Basic localhost scan
run_demo "Demo 1: Basic Localhost Scan" "python3 port_scanner.py localhost -p 22,80,443 --timeout 1"

# Demo 2: Common web ports
run_demo "Demo 2: Web Server Ports" "python3 port_scanner.py 127.0.0.1 -p 80,443,8080,8443 --timeout 1"

# Demo 3: Database ports
run_demo "Demo 3: Database Ports" "python3 port_scanner.py localhost -p 3306,5432,6379,27017 --timeout 1"

# Demo 4: High thread count
run_demo "Demo 4: High Performance Scan" "python3 port_scanner.py 127.0.0.1 -p 1-100 -t 200 --timeout 0.5"

# Demo 5: Help display
echo "🔍 Demo 5: Help and Options"
echo "Command: python3 port_scanner.py --help"
echo "─" * 50
python3 port_scanner.py --help
echo ""
echo "Press Enter to continue..."
read -r
echo ""

echo "🎉 Demo completed!"
echo ""
echo "Key Features Demonstrated:"
echo "✅ Beautiful ASCII art logo"
echo "✅ Multiple scan types (TCP, SYN, UDP)"
echo "✅ Configurable thread count for performance"
echo "✅ Customizable port ranges"
echo "✅ Service detection"
echo "✅ Comprehensive output formatting"
echo "✅ Graceful error handling"
echo ""
echo "Made with love by n0vember ❤️"
