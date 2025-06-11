import tempfile
import subprocess
import json
import os
import csv
import json
import re

from collections import defaultdict, deque
from flask import jsonify, request
from flask_login import login_required, current_user

from flask_app.blueprint import base
from flask_app.config.db_pool import engine_cert
from flask_app.logger.logger import flask_logger    

from backend.config.path_config import ROOT_DIR
from backend.parser.cert_parser_base import X509CertParser
from backend.parser.pem_parser import PEMParser


@base.route('/system/cert_search/', methods=['GET'])
@login_required
def cert_search():
    flask_logger.info(f"{request.args}")

    if 'certID' in request.args:

        conn = engine_cert.raw_connection()
        cursor = conn.cursor()
        query = f"""
            SELECT * FROM tlshandshake
            WHERE JSON_CONTAINS (cert_hash_list, %s)
            LIMIT 200
        """
        cursor.execute(query, (json.dumps([cert_sha256]), ))
        rows = cursor.fetchall()
        cursor.close()

        return [row[2] for row in rows]

    cert_parsed = PEMParser.parse_native_pretty(cert_raw)

    return jsonify({'msg': '操作成功', 'code': 200, "data": })



# @deprecated
# @base.route('/system/cert_retrive/<cert_id>', methods=['GET'])
# @login_required
# def get_cert_info(cert_id):

#     cert_raw = CertStore.query.get(cert_id).get_raw()
#     cert_parsed = PEMParser.parse_native_pretty(cert_raw)

#     # filters = []
#     # filters.append(CertScanMeta.CERT_ID == cert_id)
#     # scan_metas = CertScanMeta.query.filter(*filters)

#     return jsonify({'code': 200, 'msg': '操作成功', "cert_data" : cert_parsed, "scan_info" : []})
#     # return jsonify({'code': 200, 'msg': '操作成功', "cert_data" : parser.to_json(), "scan_info" : [scan_meta.to_json() for scan_meta in scan_metas]})


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
