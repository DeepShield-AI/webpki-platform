
import base64
import json, math
from datetime import datetime
from flask import jsonify, request, Response
from flask_login import login_required, current_user

from flask_app.blueprint import base
from flask_app.logger.logger import flask_logger    

from backend.celery.celery_db_pool import engine_cert, engine_tls
from backend.parser.asn1_parser import ASN1Parser
from backend.analyzer.celery_cag_task import cag_add_cert_parse, cag_add_cert_chain
from backend.analyzer.celery_cert_security_task import _cert_security_analyze
from backend.analyzer.celery_cert_revocation_task import get_revocation_status_from_crl, get_revocation_status_from_ocsp, get_issuer

def json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')  # 将 bytes 转换为 Base64 编码的字符串
    if isinstance(obj, bytearray):
        return base64.b64encode(obj).decode('utf-8')

    # 可以扩展支持其他类型
    return str(obj)  # fallback: 转成字符串

@base.route('/cert/cert_search/search', methods=['GET'])
@login_required
def cert_search():
    flask_logger.info(f"{request.args}")

    # 参数获取
    id = request.args.get('id', "")
    cert_sha256 = request.args.get('sha256', "")
    subject = request.args.get('subject', "")
    begin_not_valid_before = request.args.get('params[beginNotValidBefore]', "")
    end_not_valid_before = request.args.get('params[endNotValidBefore]', "")
    begin_not_valid_after = request.args.get('params[beginNotValidAfter]', "")
    end_not_valid_after = request.args.get('params[endNotValidAfter]', "")

    page = request.args.get('pageNum', 1, type=int)
    page_size = request.args.get('pageSize', 30, type=int)
    offset = (page - 1) * page_size

    where_clauses = []
    params = []

    if id:
        where_clauses.append("id = %s")
        params.append(id)

    if cert_sha256:
        where_clauses.append("sha256 = %s")
        params.append(cert_sha256)

    if subject:
        where_clauses.append("subject_cn_list LIKE %s")
        params.append(f"%{subject}%")

    if begin_not_valid_before:
        where_clauses.append("not_valid_before >= %s")
        params.append(begin_not_valid_before)

    if end_not_valid_before:
        where_clauses.append("not_valid_before <= %s")
        params.append(end_not_valid_before)

    if begin_not_valid_after:
        where_clauses.append("not_valid_after >= %s")
        params.append(begin_not_valid_after)

    if end_not_valid_after:
        where_clauses.append("not_valid_after <= %s")
        params.append(end_not_valid_after)

    where_sql = " AND ".join(where_clauses)
    if where_sql:
        where_sql = "WHERE " + where_sql

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        # 总数
        count_query = f"SELECT COUNT(*) FROM cert_search {where_sql}"
        cursor.execute(count_query, tuple(params))
        total = cursor.fetchone()[0]

        # 数据查询
        data_query = f"""
            SELECT * FROM cert_search
            {where_sql}
            LIMIT %s OFFSET %s
        """
        cursor.execute(data_query, tuple(params + [page_size, offset]))
        rows = cursor.fetchall()

        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]

    print(result)
    return jsonify({
        'code': 200,
        'msg': 'success',
        'total': total,
        'data': result
    })

    '''
        TODO: for some tables that has complicated search queries, try to use Flask-SQLAlchemy
    '''

    # filters = []
    # if 'certID' in request.args:
    #     filters.append(CertStore.CERT_ID == request.args['certID'])

    # if 'certID' in request.args:
    #     filters.append(CertStoreContent.CERT_ID == request.args['certID'])
    # if 'certDomain' in request.args:
    #     # filters.append(CertStoreContent.SUBJECT_CN == request.args['certDomain'])
    #     filters.append(CertStoreContent.SUBJECT_CN.like('%' + request.args['certDomain'] + '%'))

    # if 'params[beginNotValidBefore]' in request.args and 'params[endNotValidBefore]' in request.args:
    #     filters.append(CertStoreContent.NOT_VALID_BEFORE >= request.args['params[beginNotValidBefore]'])
    #     filters.append(CertStoreContent.NOT_VALID_BEFORE <= request.args['params[endNotValidBefore]'])
    # if 'params[beginNotValidAfter]' in request.args and 'params[beginNotValidAfter]' in request.args:
    #     filters.append(CertStoreContent.NOT_VALID_AFTER >= request.args['params[beginNotValidAfter]'])
    #     filters.append(CertStoreContent.NOT_VALID_AFTER <= request.args['params[beginNotValidAfter]'])

    # page = request.args.get('pageNum', 1, type=int)
    # rows = request.args.get('pageSize', 30, type=int)
    # pagination = CertStore.query.filter(*filters).paginate(
    #     page=page, per_page=rows, error_out=False)
    # search_certs = pagination.items

    # return jsonify({'msg': '操作成功', 'code': 200, "data": [search_cert.to_json() for search_cert in search_certs], "total" : pagination.total})


@base.route('/cert/cert_retrieve/<cert_id>', methods=['GET'])
@login_required
def get_cert_info(cert_id):

    flask_logger.info(f"{request.args}")

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT * FROM cert
            WHERE id = %s
        """
        cursor.execute(query, (cert_id,))
        row = cursor.fetchone()

    # print(row)
    if not row:
        return jsonify({'msg': 'No Such Cert', 'code': 404})

    cert_parsed = ASN1Parser.parse_der_native_pretty(row[2])
    analyze_result = _cert_security_analyze(row[1], row[2])

    try:
        modulus = cert_parsed['tbs_certificate']['subject_public_key_info']['public_key']['modulus']
        modulus = hex(modulus).upper().replace('0X', '')
        cert_parsed['tbs_certificate']['subject_public_key_info']['public_key']['modulus'] = modulus
    except:
        # probably be ec key
        pass

    conn.close()
    return Response(
        json.dumps({
            'msg': 'Success',
            'code': 200,
            'cert_data': cert_parsed,
            'cert_security': analyze_result
        }, default=json_default),
        mimetype='application/json'
    )


@base.route('/cert/cert_retrieve/<cert_id>/deploy', methods=['GET'])
@login_required
def get_cert_deploy_info(cert_id):

    flask_logger.info(f"{request.args}")

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT * FROM cert
            WHERE id = %s
        """
        cursor.execute(query, (cert_id,))
        row = cursor.fetchone()

    if not row:
        return jsonify({'msg': 'No Cert Found', 'code': 404})

    cert_sha256 = row[1]

    conn = engine_tls.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT t.*
            FROM tlshandshake t
            JOIN (
                SELECT destination_host, destination_ip
                FROM tlshandshake
                WHERE JSON_CONTAINS(cert_sha256_list, %s)
                GROUP BY destination_host, destination_ip
                LIMIT 200
            ) AS limited_hosts
            ON t.destination_host = limited_hosts.destination_host
            AND t.destination_ip = limited_hosts.destination_ip
            WHERE JSON_CONTAINS(t.cert_sha256_list, %s);
        """
        cursor.execute(query, (json.dumps([cert_sha256]), json.dumps([cert_sha256])))
        rows = cursor.fetchall()

        print(rows)
        if not rows:
            return jsonify({'msg': 'No Host Found', 'code': 404})

        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]

    conn.close()
    return jsonify({'msg': 'Success', 'code': 200, "deploy_hosts": result})


@base.route('/cert/cert_retrieve/<cert_id>/revoke', methods=['GET'])
@login_required
def get_cert_revoke_info(cert_id):
    flask_logger.info(f"{request.args}")

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT r.*
            FROM cert_revocation r
            INNER JOIN (
                SELECT dist_point, MAX(request_time) AS latest_time
                FROM cert_revocation
                WHERE cert_id = %s
                GROUP BY dist_point
            ) latest
            ON r.dist_point = latest.dist_point AND r.request_time = latest.latest_time
            WHERE r.cert_id = %s
            ORDER BY r.request_time DESC;
        """
        cursor.execute(query, (cert_id, cert_id))
        rows = cursor.fetchall()

        print(rows)
        if not rows:
            return jsonify({'msg': 'No Revoke Record Found', 'code': 200, "data": []})

        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]

    conn.close()
    return jsonify({'msg': 'Success', 'code': 200, "data": result})


@base.route('/cert/cert_retrieve/<cert_id>/get_revoke', methods=['GET'])
@login_required
def check_revoke(cert_id):
    flask_logger.info(f"{request.args}")

    type = request.args.get('type', "")
    dist_point = request.args.get('dist_point', "")

    conn = engine_cert.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT * from cert
            WHERE id = %s
        """
        cursor.execute(query, (cert_id,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'msg': 'No Cert Found', 'code': 404})
        cert_der = row[2]
        
    if type == '0':
        print("CRL")
        res = get_revocation_status_from_crl(dist_point, cert_der)
    elif type == '1':

        print("OCSP")
        parsed: dict = ASN1Parser.parse_der_native_pretty(cert_der)
        extensions = parsed['tbs_certificate']["extensions"]
        def find_ext(name):
            if extensions:
                for e in extensions:
                    if e["extn_id"] == name:
                        return e
            return None
        aia_ext = find_ext("authority_information_access")
        if aia_ext:
            values = aia_ext["extn_value"]
            for value in values:
                if value.get("access_method", None) == "ca_issuers":
                    issuer_location = value.get("access_location", None)
                    ca_issuer = get_issuer(issuer_location)
                    if ca_issuer:
                        res = get_revocation_status_from_ocsp(dist_point, cert_der, ca_issuer)

    print(res)
    conn.close()
    return jsonify({'msg': 'Success', 'code': 200, "data": res})


@base.route('/cert/cert_retrieve/<cert_id>/get_cag', methods=['GET'])
@login_required
def get_cert_cag(cert_id):
    graph_data = cag_add_cert_parse(cert_id, None)
    graph_data = cag_add_cert_chain(cert_id, graph_data)
    graph_data = deduplicate_graph_data(graph_data)
    return jsonify({'msg': 'Success', 'code': 200, "data": graph_data})


def deduplicate_graph_data(graph_data):
    unique_nodes = {}
    unique_links = {}

    for node in graph_data.get("nodes", []):
        # 假设 'id' 是节点唯一标识符
        node_id = node["id"]
        if node_id not in unique_nodes:
            unique_nodes[node_id] = node

    for link in graph_data.get("links", []):
        # 以 source 和 target 的组合作为唯一标识
        key = (link["source"], link["target"])
        if key not in unique_links:
            unique_links[key] = link

    return {
        "nodes": list(unique_nodes.values()),
        "links": list(unique_links.values())
    }
