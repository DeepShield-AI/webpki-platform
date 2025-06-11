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

# Get the total number of certificates
@base.route('/system/cert_analysis/certs_total', methods=['GET'])
@login_required
def get_total_certs():
    conn = engine_cert.raw_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM cert")
        count = cursor.fetchone()[0]  # fetch one row and get the count
    finally:
        cursor.close()
        conn.close()

    return jsonify({'msg': 'Success', 'code': 200, 'data': count})


# Get all cert analysis status
@base.route('/system/cert_analysis/cert_security_stats', methods=['GET'])
@login_required
def get_cert_security_stats():

    error_code_list_result = defaultdict(int)
    cert_total = 0
    cert_wo_error = 0

    try:
        with open(os.path.join(ROOT_DIR, "data/frontend_result/cert_security_out/cert_security.json"), "r", encoding='utf-8-sig') as stat_file:
            for line in stat_file:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    cert_total += 1

                    error_codes = data.get("error_code", [])
                    if not error_codes:
                        cert_wo_error += 1
                    else:
                        for code in error_codes:
                            error_code_list_result[code] += 1

                except json.JSONDecodeError as e:
                    # Skip malformed lines
                    continue
    except FileNotFoundError:
        return jsonify({"msg": "cert_security.json file not found", 'code': 404})
    except Exception as e:
        return jsonify({"msg": str(e), 'code': 500})

    result = {
        "total_certificates": cert_total,
        "certificates_without_error": cert_wo_error,
        "error_statistics": dict(error_code_list_result)
    }

    return jsonify({'msg': 'Success', 'code': 200, "data": result})
