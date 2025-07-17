
from flask import jsonify, request, Response
from flask_login import login_required, current_user
from flask_app.blueprint import base
from flask_app.logger.logger import flask_logger    
from backend.celery.celery_db_pool import engine_ca

@base.route('/ca/ca_search/search', methods=['GET'])
@login_required
def ca_search():
    flask_logger.info(f"{request.args}")

    # 参数获取
    name = request.args.get('name', "")
    page = request.args.get('pageNum', 1, type=int)
    page_size = request.args.get('pageSize', 30, type=int)
    offset = (page - 1) * page_size

    where_clauses = []
    params = []

    if name:
        where_clauses.append("issuer_org like %s")
        params.append(f"%{name}%")

    where_sql = " AND ".join(where_clauses)
    if where_sql:
        where_sql = "WHERE " + where_sql

    conn = engine_ca.raw_connection()
    with conn.cursor() as cursor:
        # 总数
        count_query = f"""
            SELECT COUNT(*)
            FROM ca
            {where_sql}
        """
        cursor.execute(count_query, tuple(params))
        total = cursor.fetchone()[0]

        # 数据查询
        data_query = f"""
            SELECT id, subject FROM ca
            {where_sql}
            LIMIT %s OFFSET %s
        """
        cursor.execute(data_query, tuple(params + [page_size, offset]))
        rows = cursor.fetchall()

        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]

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


@base.route('/ca/ca_retrieve/<ca_id>', methods=['GET'])
@login_required
def get_ca_info(ca_id):

    flask_logger.info(f"{request.args}")

    conn = engine_ca.raw_connection()
    with conn.cursor() as cursor:
        query = """
            SELECT * FROM ca
            WHERE id = %s
        """
        cursor.execute(query, (ca_id,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'msg': 'Can not find CA data', 'code': 404})

        columns = [desc[0] for desc in cursor.description]
        result = dict(zip(columns, row))

    return jsonify({'msg': 'Success', 'code': 200, "data": result})
