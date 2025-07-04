
import json
from flask import jsonify, request
from flask_login import login_required, current_user
from collections import defaultdict, deque

from flask_app.blueprint import base
from flask_app.logger.logger import flask_logger    

from backend.celery.celery_db_pool import engine_cert, engine_tls
from backend.config.path_config import ROOT_DIR
from backend.parser.cert_parser_base import X509CertParser
from backend.parser.pem_parser import PEMParser
from backend.analyzer.celery_web_security_task import _web_security_analyze
from backend.utils.domain import check_input_type


@base.route('/host/host_retrieve/<host>', methods=['GET'])
@login_required
def get_host_info(host):

    flask_logger.info(f"{request.args}")

    # check if the host is domain or ip
    arg_type = check_input_type(host)
    conn = engine_tls.raw_connection()

    with conn.cursor() as cursor:
        if arg_type == "Domain":
            query = """
                SELECT * FROM tlshandshake
                WHERE destination_host = %s
            """
            cursor.execute(query, (host,))
            rows = cursor.fetchall()

        elif arg_type == "IP address":
            query = """
                SELECT * FROM tlshandshake
                WHERE destination_ip = %s
            """
            cursor.execute(query, (host,))
            rows = cursor.fetchall()

        else:
            return jsonify({'msg': 'Invalid input format', 'code': 500})

    final_result = set()
    for row in rows:
        final_result.add(json.dumps(_web_security_analyze(row, "/")))

    final_result = [json.loads(i) for i in final_result]
    print(final_result)
    return jsonify({'msg': 'Success', 'code': 200, "host_security" : final_result})
