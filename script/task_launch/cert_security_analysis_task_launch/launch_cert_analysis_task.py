
# build cag

from backend.config.analyze_config import AnalyzeConfig
from backend.analyzer.analyze_manager import AnalyzeManager

if __name__ == "__main__":
    test_config = AnalyzeConfig(
        out_dir=r"/home/tianyu/pki-internet-platform/data/frontend_result/cert_security_out",
        task_flag=AnalyzeConfig.TASK_CERT_SECURITY,
        start_id=15583729
    )
    manager = AnalyzeManager(test_config)
    manager.start()
