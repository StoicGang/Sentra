import socket
import threading
import time
from cli.daemon.network_daemon import NetworkDaemon

def test_daemon_socket_acceptance(caplog):
    # Enable caplog for INFO level since our daemon logs are at INFO
    import logging
    caplog.set_level(logging.INFO)
    
    port = 15557
    daemon = NetworkDaemon(host='127.0.0.1', port=port)
    
    # Start daemon
    daemon_thread = threading.Thread(target=daemon.run, daemon=True)
    daemon_thread.start()
    
    time.sleep(0.5) # Wait for daemon to bind
    
    # Open real TCP client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(2.0)
    try:
        client.connect(('127.0.0.1', port))
        client.sendall(b"TEST_DATA")
        time.sleep(0.5) # Wait for daemon to process
    finally:
        client.close()
        
    # Give daemon time to tear down
    time.sleep(0.5)
    
    daemon.stop()
    daemon_thread.join(timeout=2.0)
    
    # Verify logs
    log_text = caplog.text
    
    # Verify daemon logs accepted connection
    assert "Incoming connection accepted" in log_text
    assert "Remote peer IP/port:" in log_text
    
    # Verify daemon logs disconnect cleanly
    assert "Socket read start for" in log_text
    assert "Graceful connection teardown completed for" in log_text

def test_daemon_ip_whitelisting(caplog):
    import logging
    caplog.set_level(logging.INFO)
    
    port = 15558
    # Only allow 192.168.1.1, so local connection from 127.0.0.1 should be rejected
    daemon = NetworkDaemon(host='127.0.0.1', port=port, allow_ips=['192.168.1.1'])
    
    daemon_thread = threading.Thread(target=daemon.run, daemon=True)
    daemon_thread.start()
    
    time.sleep(0.5)
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(2.0)
    try:
        client.connect(('127.0.0.1', port))
        time.sleep(0.5)
        # Verify connection is closed by daemon
        data = client.recv(1024)
        assert data == b""
    finally:
        client.close()
        
    daemon.stop()
    daemon_thread.join(timeout=2.0)
    
    log_text = caplog.text
    assert "Connection rejected: IP 127.0.0.1 not in allow list" in log_text
