
import tempfile
import subprocess
import json
import os
import csv
import json
import re

from flask import jsonify, request
from flask_login import login_required, current_user
from collections import defaultdict, deque

from flask_app.blueprint import base
from flask_app.config.db_pool import engine_cert
from flask_app.logger.logger import flask_logger    

from backend.config.path_config import ROOT_DIR
from backend.parser.cert_parser_base import X509CertParser
from backend.parser.pem_parser import PEMParser
from backend.analyzer.celery_cert_security_task import _cert_security_analyze


@base.route('/system/cert_retrieve/<cert_sha256>', methods=['GET'])
@login_required
def get_cert_info(cert_sha256):

    flask_logger.info(f"{request.args}")

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT * FROM cert
            WHERE cert_hash = %s
        """
        cursor.execute(query, (cert_sha256,))
        row = cursor.fetchone()

    # print(row)
    if not row:
        return jsonify({'msg': 'No Such Cert', 'code': 404})

    cert_parsed = PEMParser.parse_native_pretty(row[1])
    analyze_result = _cert_security_analyze(row, "/")

    final_data = []
    for error_code in analyze_result["error_code"]:
        error_info = analyze_result["error_info"].get(error_code, "")
        final_data.append({
            "error_code" : error_code,
            "error_info" : error_info
        })

    print(final_data)
    return jsonify({'msg': 'Success', 'code': 200, "cert_data": cert_parsed, "cert_security" : final_data})


# @deprecated
# @base.route('/system/zlint/<cert_id>', methods=['GET'])
# @login_required
# def get_cert_zlint(cert_id):

#     cert_pem = CertStore.query.get(cert_id).get_raw()

#     """
#     调用 Zlint 验证证书。
#     :param cert_pem: str, PEM 格式的证书字符串。
#     :return: dict, Zlint 输出结果。
#     """
#     # 创建一个临时文件存储证书内容
#     with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as temp_cert_file:
#         temp_cert_file.write(cert_pem.encode())
#         temp_cert_path = temp_cert_file.name

#     try:
#         # 调用 Zlint
#         result = subprocess.run(
#             [ZLINT_PATH, temp_cert_path],
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE,
#             text=True
#         )

#         # 检查是否有错误输出
#         if result.returncode != 0:
#             raise RuntimeError(f"Zlint error: {result.stderr.strip()}")

#         # 解析 JSON 输出
#         zlint_output = json.loads(result.stdout)

#     finally:
#         # 删除临时文件
#         try:
#             import os
#             os.unlink(temp_cert_path)
#         except OSError:
#             pass

#     return jsonify({'code': 200, 'msg': '操作成功', "zlint_result" : zlint_output})
