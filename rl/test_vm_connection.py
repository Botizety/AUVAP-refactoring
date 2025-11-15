"""Test remote VM executor connectivity and script execution."""

import sys
from pathlib import Path

# Add auvap to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rl.remote_executor import create_remote_executor_from_env


def test_vm_connection():
    """Test basic SSH connection to VM."""
    
    executor = create_remote_executor_from_env()
    if not executor:
        print("❌ Remote VM not configured")
        print()
        print("Set environment variables:")
        print("  export RL_VM_HOST=<vm_ip>")
        print("  export RL_VM_USER=<username>")
        print("  export RL_VM_KEY_PATH=<ssh_key_path>  # or RL_VM_PASSWORD")
        print()
        print("Example:")
        print("  source rl/vm_config.env")
        return False
    
    print(f"Testing connection to {executor.vm_user}@{executor.vm_host}:{executor.vm_port}")
    
    try:
        executor.connect()
        print("✓ SSH connection successful")
        
        # Test command execution
        stdout, stderr, exit_code = executor._exec_command("echo 'Hello from VM'")
        if exit_code == 0 and "Hello from VM" in stdout:
            print("✓ Command execution successful")
        else:
            print(f"❌ Command execution failed: {stderr}")
            return False
        
        # Test Python availability
        stdout, stderr, exit_code = executor._exec_command(f"{executor.python_path} --version")
        if exit_code == 0:
            print(f"✓ Python available on VM: {stdout.strip()}")
        else:
            print(f"❌ Python not found: {stderr}")
            return False
        
        # Test workspace creation
        stdout, stderr, exit_code = executor._exec_command(f"ls -la {executor.workspace_dir}")
        if exit_code == 0:
            print(f"✓ Workspace directory ready: {executor.workspace_dir}")
        else:
            print(f"⚠ Workspace not found (will be created): {executor.workspace_dir}")
        
        executor.disconnect()
        print("✓ Connection closed cleanly")
        return True
        
    except Exception as exc:
        print(f"❌ Connection failed: {exc}")
        return False


def test_script_execution():
    """Test actual exploit script execution on VM."""
    
    executor = create_remote_executor_from_env()
    if not executor:
        print("❌ Remote VM not configured")
        return False
    
    print()
    print("Testing exploit script execution on VM...")
    
    # Mock vulnerability
    vuln = {
        "vuln_id": "TEST-VM-001",
        "host": "127.0.0.1",  # VM will target its own localhost
        "port": 22,
        "service": "ssh",
    }
    
    # Simple test script
    test_script = """
import socket
import time

def exploit(target_ip, target_port):
    '''Test script - just checks if port is open.'''
    
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        result = sock.connect_ex((target_ip, int(target_port)))
        sock.close()
        elapsed = time.time() - start
        
        if result == 0:
            return {
                "success": True,
                "message": f"Port {target_port} is open",
                "evidence": f"Connected to {target_ip}:{target_port} in {elapsed:.2f}s",
            }
        else:
            return {
                "success": False,
                "message": f"Port {target_port} is closed or filtered",
                "evidence": f"Connection failed with code {result}",
            }
    except Exception as exc:
        return {
            "success": False,
            "message": "Connection failed",
            "evidence": str(exc),
        }
"""
    
    try:
        executor.connect()
        result = executor.execute_script_remote(vuln, test_script, timeout=10)
        
        print(f"  Success: {result.get('success')}")
        print(f"  Message: {result.get('message')}")
        print(f"  Evidence: {result.get('evidence')}")
        print(f"  Execution time: {result.get('execution_time', 0):.2f}s")
        
        if result.get("success"):
            print("✓ Script executed successfully on VM")
        else:
            print("⚠ Script executed but reported failure (expected for test)")
        
        executor.disconnect()
        return True
        
    except Exception as exc:
        print(f"❌ Execution failed: {exc}")
        return False


def main():
    """Run VM connectivity tests."""
    
    print("=" * 60)
    print("AUVAP Remote VM Executor Test")
    print("=" * 60)
    print()
    
    # Test 1: Connection
    print("[1/2] Testing VM connection...")
    conn_ok = test_vm_connection()
    
    if not conn_ok:
        print()
        print("=" * 60)
        print("❌ Connection test failed")
        print("=" * 60)
        return 1
    
    # Test 2: Script execution
    print()
    print("[2/2] Testing script execution...")
    exec_ok = test_script_execution()
    
    print()
    print("=" * 60)
    if conn_ok and exec_ok:
        print("✓ All tests passed! Remote VM is ready for PPO training.")
        print()
        print("Next steps:")
        print("1. Ensure VM has VPN connection to target network")
        print("2. Run PPO training with remote execution:")
        print("   source rl/vm_config.env")
        print("   python main.py --nessus scan.nessus --config config.json --rl-mode train")
    else:
        print("❌ Some tests failed. Check configuration and try again.")
    print("=" * 60)
    
    return 0 if (conn_ok and exec_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
