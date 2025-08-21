#!/bin/bash

# Port Scanner Installation Script
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
echo "Installing Port Scanner..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed. Please install Python 3.6+ first."
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.6"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.6+ is required. Current version: $python_version"
    exit 1
fi

echo "✅ Python 3 version $python_version detected"

# Create installation directory
install_dir="/usr/local/bin"
script_name="portscanner"

# Check if running as root for system-wide installation
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Not running as root. Installing to user directory..."
    install_dir="$HOME/.local/bin"
    mkdir -p "$install_dir"
fi

# Copy the scanner script
if cp port_scanner.py "$install_dir/$script_name"; then
    echo "✅ Port scanner installed to $install_dir/$script_name"
else
    echo "❌ Failed to install port scanner"
    exit 1
fi

# Make it executable
chmod +x "$install_dir/$script_name"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$install_dir:"* ]]; then
    if [ "$EUID" -eq 0 ]; then
        echo "export PATH=\"$install_dir:\$PATH\"" >> /etc/profile
        echo "✅ Added to system PATH"
    else
        echo "export PATH=\"$install_dir:\$PATH\"" >> "$HOME/.bashrc"
        echo "✅ Added to user PATH (restart terminal or run 'source ~/.bashrc')"
    fi
fi

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "Usage examples:"
echo "  $script_name 192.168.1.1"
echo "  $script_name example.com -p 80,443,8080"
echo "  $script_name localhost -t 200"
echo ""
echo "For more options, run: $script_name --help"
echo ""
echo "Made with love by n0vember ❤️"
