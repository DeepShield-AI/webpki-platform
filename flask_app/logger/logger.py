
import logging
import os
from datetime import datetime, timezone
import colorama
from colorama import Fore, Style

from backend.config.config_loader import FLASK_LOGGER_DIR

colorama.init(autoreset=True)

class ColoredConsoleHandler(logging.StreamHandler):
    COLOR_MAP = {
        logging.DEBUG: Fore.GREEN,
        logging.INFO: Fore.BLUE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED,
    }

    def emit(self, record):
        color = self.COLOR_MAP.get(record.levelno, Fore.WHITE)
        message = self.format(record)
        message = f"{color}{message}{Style.RESET_ALL}"
        print(message)

def get_logger(name="Flask",
               log_file_dir="/data/platform_log",
               level=logging.INFO,
               file_level=logging.INFO,
               console_level=logging.DEBUG):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s')

        # Console handler (with color)
        ch = ColoredConsoleHandler()
        ch.setLevel(console_level)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # File handler
        if log_file_dir:
            os.makedirs(log_file_dir, exist_ok=True)
            now = datetime.now(timezone.utc)
            file_name = now.strftime("%Y-%m-%d_%H_%M_%S.log")
            file_path = os.path.join(log_file_dir, file_name)

            fh = logging.FileHandler(file_path)
            fh.setLevel(file_level)
            fh.setFormatter(formatter)
            logger.addHandler(fh)

    return logger

flask_logger = get_logger("Flask", log_file_dir=FLASK_LOGGER_DIR, level=logging.DEBUG)
