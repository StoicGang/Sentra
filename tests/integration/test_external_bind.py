import socket
import threading
import time
import pytest
from unittest.mock import patch
from cli.daemon.network_daemon import NetworkDaemon

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

def test_daemon_binds_externally():
    port = 15555
    daemon = NetworkDaemon(host='0.0.0.0', port=port)
    
    daemon_thread = threading.Thread(target=daemon.run, daemon=True)
    daemon_thread.start()
    
    time.sleep(0.5) # Wait for daemon to start listening
    
    try:
        # Test connecting via localhost
        with socket.create_connection(('127.0.0.1', port), timeout=2) as conn:
            assert conn is not None
            
        # Test connecting via external LAN IP
        local_ip = get_local_ip()
        with socket.create_connection((local_ip, port), timeout=2) as conn:
            assert conn is not None
            
    finally:
        daemon.stop()
        daemon_thread.join(timeout=1.0)

def test_daemon_bind_failure_logged(caplog):
    port = 15556
    # Bind a socket manually to block the port
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(('0.0.0.0', port))
    blocker.listen(1)
    
    daemon = NetworkDaemon(host='0.0.0.0', port=port)
    
    try:
        with pytest.raises(OSError):
            daemon.run()
            
        assert "Socket startup failure" in caplog.text
    finally:
        blocker.close()
