
import base64
import os, csv, sys
from backend.analyzer.celery_cert_security_task import _cert_security_analyze
from backend.utils.cert import get_sha256_hex_from_bytes
from pprint import pprint

test_path = os.path.join(os.path.dirname(__file__), sys.argv[1])

label_num = 0
label_correct = 0

with open(test_path, 'r') as f:
    reader = csv.reader(f)
    
    for data in reader:
        base64_cert, label = data[0], data[1]
        label_num += 1

        der_bytes = base64.decodebytes(base64_cert.encode('ascii'))  # base64 string → DER
        analyze_result = _cert_security_analyze(get_sha256_hex_from_bytes(der_bytes), der_bytes)
        pprint(analyze_result)

        if analyze_result["error_code"] and label == "bad":
            label_correct += 1
        elif not analyze_result["error_code"] and label == "good":
            label_correct += 1

print("Result:")
print(f"Total test cert num: {label_num}")
print(f"Correct predict num: {label_correct}")
print(f"Analyze accuracy: {label_correct / label_num}")
