
from backend.utils.type import ScanType

def test_scan_type_enum():
    assert ScanType.SCAN_BY_CT.value == 2
    assert isinstance(ScanType.SCAN_BY_DOMAIN, ScanType)
    assert isinstance(ScanType.SCAN_BY_IP, ScanType)
