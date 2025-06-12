
import os
import csv
import json
import re

from collections import defaultdict, deque
from flask import jsonify, request
from flask_login import login_required, current_user

from flask_app.blueprint import base
from flask_app.config.db_pool import engine_cert, engine_tls
from flask_app.logger.logger import flask_logger    

from backend.config.path_config import ROOT_DIR


# Get the total number of tls connections
@base.route('/system/host_analysis/hosts_total', methods=['GET'])
@login_required
def get_total_host():
    conn = engine_tls.raw_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM tlshandshake")
        count = cursor.fetchone()[0]  # fetch one row and get the count
    finally:
        cursor.close()
        conn.close()

    return jsonify({'msg': 'Success', 'code': 200, 'data': count})


# Get all web analysis status
@base.route('/system/host_analysis/host_security_stats', methods=['GET'])
@login_required
def get_host_security_stats():

    error_code_list_result = defaultdict(int)
    web_total = 0
    web_wo_error = 0

    try:
        with open(os.path.join(ROOT_DIR, "data/frontend_result/web_security_out/web_security.json"), "r", encoding='utf-8-sig') as stat_file:
            for line in stat_file:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    web_total += 1

                    error_codes = data.get("error_code", [])
                    if not error_codes:
                        web_wo_error += 1
                    else:
                        for code in error_codes:
                            error_code_list_result[code] += 1

                except json.JSONDecodeError as e:
                    # Skip malformed lines
                    continue
    except FileNotFoundError:
        return jsonify({"msg": "web_security.json file not found", 'code': 404})
    except Exception as e:
        return jsonify({"msg": str(e), 'code': 500})

    result = {
        "total_webs": web_total,
        "webs_without_error": web_wo_error,
        "error_statistics": dict(error_code_list_result)
    }

    return jsonify({'msg': 'Success', 'code': 200, "data": result})
