
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
@base.route('/host/host_analysis/hosts_total', methods=['GET'])
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
@base.route('/host/host_analysis/host_security_stats', methods=['GET'])
@login_required
def get_host_security_stats():

    error_code_list_result = defaultdict(int)
    tls_total = 0
    tls_wo_error = 0

    try:
        with open(os.path.join(ROOT_DIR, "data/frontend_result/web_security_out/web_security.json"), "r", encoding='utf-8-sig') as stat_file:
            for line in stat_file:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    tls_total += 1

                    error_codes = data.get("error_code", [])
                    if not error_codes:
                        tls_wo_error += 1
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
        "total_hosts": tls_total,
        "hosts_without_error": tls_wo_error,
        "error_statistics": dict(error_code_list_result)
    }

    return jsonify({'msg': 'Success', 'code': 200, "data": result})


@base.route('/host/host_analysis/sub_cag', methods=['GET'])
@login_required
def get_sub_cag():

    node_data = {}  # key: node_id -> value: {"name": ..., "type": ...}
    edge_data = defaultdict(list)  # key: source_node_id -> list of (target_id, edge_type)

    # Load edge data
    with open(os.path.join(ROOT_DIR, "data/frontend_result/cag_out/cag_edge.csv"), "r", encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        for row in reader:
            edge_type = row[0]
            n1 = row[1]
            n2 = row[2]
            edge_data[n1].append((n2, edge_type))

    # Load node data
    with open(os.path.join(ROOT_DIR, "data/frontend_result/cag_out/cag_node.csv"), "r", encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        for row in reader:
            node_id = row[0]
            node_data[node_id] = {
                "name": row[1],
                "type": row[2]
            }

    # Find all domain nodes matching *.gov.tw
    root_nodes = set()
    for node_id, info in node_data.items():
        if info["type"].lower() == "domain" and re.search(r"\.gov\.tw$", info["name"], re.IGNORECASE):
            root_nodes.add(node_id)

    # BFS for depth = 2 from each root node
    visited = set()
    sub_cag_nodes = {}
    sub_cag_edges = set()

    for root_id in root_nodes:
        queue = deque([(root_id, 0)])
        visited.add(root_id)

        while queue:
            current, depth = queue.popleft()
            if current not in node_data:
                continue
            sub_cag_nodes[current] = node_data[current]

            if depth < 2:
                for neighbor, e_type in edge_data.get(current, []):
                    sub_cag_edges.add((current, neighbor, e_type))
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, depth + 1))

    # Build final graph
    graph_data = {
        "nodes": [],
        "links": []
    }

    for node_id, info in sub_cag_nodes.items():
        graph_data["nodes"].append({
            "id": node_id,
            "name": info["name"],
            "type": info["type"].lower(),
            "root": node_id in root_nodes
        })

    for src, tgt, e_type in sub_cag_edges:
        graph_data["links"].append({
            "source": src,
            "target": tgt,
            "type": e_type
        })

    flask_logger.info(json.dumps(graph_data, indent=4))
    return jsonify({'msg': 'Success', 'code': 200, "data": graph_data})
