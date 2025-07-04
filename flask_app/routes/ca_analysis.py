
from collections import defaultdict
from flask import jsonify, request
from flask_login import login_required, current_user

from flask_app.blueprint import base
from flask_app.logger.logger import flask_logger
from backend.celery.celery_db_pool import engine_cert, engine_tls

def stream_ca(table_name="cert_search", batch_size=1000, start_hash=""):
    """
    Incrementally stream (sha256, issuer_org) pairs from the cert table,
    ordered by sha256 to support resumable iteration.
    """
    conn = engine_cert.raw_connection()
    cursor = conn.cursor()
    last_hash = start_hash

    try:
        while True:
            if last_hash:
                query = f"""
                    SELECT sha256, issuer_org FROM {table_name}
                    WHERE sha256 > %s
                    ORDER BY sha256 ASC
                    LIMIT %s
                """
                cursor.execute(query, (last_hash, batch_size))
            else:
                query = f"""
                    SELECT sha256, issuer_org FROM {table_name}
                    ORDER BY sha256 ASC
                    LIMIT %s
                """
                cursor.execute(query, (batch_size,))
            
            rows = cursor.fetchall()
            if not rows:
                break

            for sha256, issuer_org in rows:
                yield issuer_org
            last_hash = rows[-1][0]  # sha256 of the last row

    finally:
        cursor.close()
        conn.close()


@base.route('/ca/ca_analysis/ca_stats', methods=['GET'])
@login_required
def get_ca_stats():
    """
    Endpoint: /ca/ca_analysis/ca_stats
    Description: Returns a count of certificates grouped by issuer_org.
    """
    flask_logger.info(f"[CA_STATS] Request args: {request.args}")

    ca_info = defaultdict(int)
    for issuer_org in stream_ca():
        if issuer_org is None: ca_info["Unknown"] += 1
        else: ca_info[issuer_org] += 1

    print(ca_info)
    # jsonify may fail on defaultdict, so convert to dict
    return jsonify({
        'msg': 'Success',
        'code': 200,
        'data': ca_info
    })
