import socket
import logging

def run_debug_transport(host: str, port: int):
    logger = logging.getLogger("DebugTransport")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
    logger.info(f"Starting transport reachability test to {host}:{port}")
    
    try:
        logger.info("Initializing raw TCP socket")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        
        logger.info(f"Attempting TCP connect to {host}:{port}")
        s.connect((host, port))
        logger.info(f"Socket connect success! Local address: {s.getsockname()}")
        
        logger.info("Logging handshake attempt...")
        handshake_payload = b"DEBUG_HANDSHAKE_PROBE"
        logger.info(f"Sending probe payload: {handshake_payload}")
        s.sendall(handshake_payload)
        
        logger.info("Awaiting response (socket read start)...")
        data = s.recv(1024)
        if not data:
            logger.info("Socket disconnect (EOF) from remote peer")
        else:
            logger.info(f"Received response: {data}")
            
        logger.info("Transport reachability verified successfully.")
        
    except socket.timeout:
        logger.error("Socket operation timed out.")
    except ConnectionRefusedError:
        logger.error("Connection refused. Is the daemon running on the target port?")
    except Exception as e:
        logger.error(f"Socket exception: {e}")
    finally:
        logger.info("Initiating graceful socket teardown")
        try:
            s.close()
            logger.info("Socket closed successfully")
        except Exception as e:
            logger.error(f"Error closing socket: {e}")
