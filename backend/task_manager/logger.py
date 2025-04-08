
import logging

my_logger = logging.getLogger("TaskManager")
my_logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
my_logger.addHandler(ch)
