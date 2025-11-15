#!/bin/bash
# Quick setup script for Metasploitable2 remote execution

echo "==================================================="
echo "AUVAP PPO - Metasploitable2 Remote Execution Setup"
echo "==================================================="
echo

# Check if VM IP is provided
if [ -z "$1" ]; then
    echo "Usage: ./setup_metasploitable2.sh <metasploitable2_ip>"
    echo
    echo "Example:"
    echo "  ./setup_metasploitable2.sh 192.168.1.100"
    echo
    exit 1
fi

METASPLOITABLE2_IP="$1"

echo "Testing connection to Metasploitable2 at $METASPLOITABLE2_IP..."
echo

# Test basic connectivity
if ! ping -c 1 -W 2 "$METASPLOITABLE2_IP" > /dev/null 2>&1; then
    echo "❌ Cannot reach $METASPLOITABLE2_IP"
    echo "   Make sure Metasploitable2 VM is running and network is configured"
    exit 1
fi

echo "✓ VM is reachable"

# Test SSH connectivity with default credentials
echo "Testing SSH connection (msfadmin:msfadmin)..."

if sshpass -p "msfadmin" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    msfadmin@"$METASPLOITABLE2_IP" "echo 'SSH OK'" > /dev/null 2>&1; then
    echo "✓ SSH connection successful"
else
    echo "❌ SSH connection failed"
    echo "   Install sshpass: brew install hudochenkov/sshpass/sshpass"
    echo "   Or test manually: ssh msfadmin@$METASPLOITABLE2_IP (password: msfadmin)"
    exit 1
fi

# Create VM config file
CONFIG_FILE="rl/vm_config.env"

cat > "$CONFIG_FILE" << EOF
#!/bin/bash
# Metasploitable2 VM configuration (auto-generated)

export RL_VM_HOST="$METASPLOITABLE2_IP"
export RL_VM_PORT="22"
export RL_VM_USER="msfadmin"
export RL_VM_PASSWORD="msfadmin"
export RL_VM_PYTHON="python"
export RL_VM_WORKSPACE="/tmp/auvap_rl"
EOF

chmod +x "$CONFIG_FILE"

echo "✓ Created configuration file: $CONFIG_FILE"
echo

# Load and test
source "$CONFIG_FILE"

echo "Testing Python availability on VM..."
if sshpass -p "msfadmin" ssh -o StrictHostKeyChecking=no msfadmin@"$METASPLOITABLE2_IP" \
    "python -c 'import sys; print(sys.version)'" 2>/dev/null | head -1; then
    echo "✓ Python is available"
else
    echo "⚠ Python test failed (may still work)"
fi

echo
echo "==================================================="
echo "✓ Setup complete!"
echo "==================================================="
echo
echo "Next steps:"
echo "1. Load configuration:"
echo "   source $CONFIG_FILE"
echo
echo "2. Test remote execution:"
echo "   python rl/test_vm_connection.py"
echo
echo "3. Train PPO with Metasploitable2:"
echo "   python main.py --nessus Meta_hvp1r9.nessus --config config/context_rules.json --rl-mode train"
echo
echo "⚠️  SECURITY WARNING:"
echo "   Metasploitable2 is EXTREMELY vulnerable by design."
echo "   Only use in isolated lab environments."
echo "   Never connect to untrusted networks."
echo
