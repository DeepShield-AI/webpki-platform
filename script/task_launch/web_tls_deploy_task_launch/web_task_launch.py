
# build cag

from backend.config.analyze_config import AnalyzeConfig
from backend.analyzer.analyze_manager import AnalyzeManager

if __name__ == "__main__":
    test_config = AnalyzeConfig(
        out_dir=r"/home/tianyu/pki-internet-platform/data/frontend_result/web_security_out",
        task_flag=AnalyzeConfig.TASK_WEB_SECURITY,
        start_id=4518586
    )
    manager = AnalyzeManager(test_config)
    manager.start()
