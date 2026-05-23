"""
Tests for Sync Daemon Startup
"""
import pytest
import threading
import time
from cli.daemon.network_daemon import NetworkDaemon

def test_daemon_startup_and_shutdown():
    daemon = NetworkDaemon(port=5556)
    
    # Run in thread
    t = threading.Thread(target=daemon.run)
    t.daemon = True
    t.start()
    
    time.sleep(0.5)
    assert daemon.running is True
    
    daemon.stop()
    t.join(timeout=2.0)
    assert daemon.running is False
