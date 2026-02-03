import os
import sys
from pathlib import Path
from pck67_pkg import TrackingClient

def login():
    """Interactive login - saves API key to .env"""
    print("🔐 pck67_pkg Login")
    print("-" * 40)
    
    # Get API key from user
    api_key = input("Enter your TRACKING_API_KEY: ").strip()
    
    if not api_key:
        print("❌ Error: API key cannot be empty")
        sys.exit(1)
    
    # Verify API key by calling /users/me
    try:
        client = TrackingClient(api_key=api_key)
        user = client.get_current_user()
        
        # Save to .env in current directory
        env_path = Path.cwd() / ".env"
        
        # Read existing .env if it exists
        existing_lines = []
        if env_path.exists():
            with open(env_path, 'r') as f:
                existing_lines = [line for line in f.readlines() 
                                if not line.startswith("TRACKING_API_KEY=")]
        
        # Write .env with new API key
        with open(env_path, 'w') as f:
            f.write(f"TRACKING_API_KEY={api_key}\n")
            for line in existing_lines:
                f.write(line)
        
        print(f"✅ Login successful!")
        print(f"👤 User: {user['username']} ({user['email']})")
        print(f"💾 API key saved to: {env_path}")
        
    except Exception as e:
        print(f"❌ Login failed: {e}")
        print("🔍 Check your API key or server connection")
        sys.exit(1)


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage: pck67 <command>")
        print("Commands:")
        print("  login    - Login with API key")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "login":
        login()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()