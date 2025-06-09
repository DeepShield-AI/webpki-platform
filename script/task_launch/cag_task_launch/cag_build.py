
# build cag

from backend.config.analyze_config import AnalyzeConfig
from backend.analyzer.analyze_manager import AnalyzeManager

if __name__ == "__main__":
    test_config = AnalyzeConfig(
        out_dir=r"/data/cag_out",
        task_flag=0b1000
    )
    manager = AnalyzeManager(test_config)
    manager.start()
