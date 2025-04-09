
'''
    Manager base class
'''
from backend.logger.logger import primary_logger
import signal
import sys

def signal_handler(sig, frame):
    primary_logger.warning("Ctrl+C detected")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
primary_logger.info("Crtl+C signal handler attached!")
