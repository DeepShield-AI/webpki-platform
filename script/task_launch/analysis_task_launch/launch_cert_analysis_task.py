
# build cert fps for all certs in table cert.cert

from backend.config.analyze_config import AnalyzeConfig
from backend.analyzer.analyze_manager import AnalyzeManager

if __name__ == "__main__":
    test_config = AnalyzeConfig()
    manager = AnalyzeManager(test_config)
    manager.start()
