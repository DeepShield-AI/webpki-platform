
from backend.config.analyze_config import AnalyzeConfig
from backend.analyzer.analyze_manager import AnalyzeManager

if __name__ == "__main__":
    test_config = AnalyzeConfig(
        out_dir=r"/root/tianyu/pki-internet-platform/data/frontend_result/cert_security_out",
        task_flag=AnalyzeConfig.TASK_CERT_TRUST,
        start_id=12564280
    )
    manager = AnalyzeManager(test_config)
    manager.start()
