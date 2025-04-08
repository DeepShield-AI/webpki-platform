
from backend.logger.logger import get_logger
from pathlib import Path
import logging
import shutil
import os

def test_custom_log():

    current_dir_path = str(Path(__file__).resolve().parent).replace("\\", "/")
    output_dir = current_dir_path + r"/out"

    # rm any cached files first
    if Path(output_dir).exists():
        shutil.rmtree(output_dir)

    custom_logger = get_logger("Custom", log_file_dir=output_dir, level=logging.DEBUG)

    custom_logger.info("LoggerInitialized.")
    custom_logger.warning("SomethingMightGoWrong.")
    custom_logger.error("SomethingWentWrong!")

    for file in os.scandir(output_dir):
        if os.path.isfile(file):
            with open(file, "r") as out:
                for i, line in enumerate(out.readlines()):
                    line: str
                    last_info = line.strip().split(" ")[-1]
                    if i == 0:
                        assert last_info == "LoggerInitialized."
                    elif i == 1:
                        assert last_info == "SomethingMightGoWrong."
                    elif i == 2:
                        assert last_info == "SomethingWentWrong!"
