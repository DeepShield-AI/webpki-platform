
import json
import hashlib
from collections import OrderedDict

def get_sha256_hex_from_str(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def reorder_issuer_and_sha256(issuer_dict):
    keys_order = ["common_name", "country_name", "organization_name", "organizational_unit_name"]

    ordered = OrderedDict()
    for k in keys_order:
        if k in issuer_dict:
            ordered[k] = issuer_dict[k]

    issuer_json_str = json.dumps(ordered, separators=(', ', ': '), ensure_ascii=False)
    print("JSON string used for hashing:", repr(issuer_json_str))
    return get_sha256_hex_from_str(issuer_json_str)

# 举个例子
issuer = {
    "common_name": "RapidSSL TLS RSA CA G1",
    "country_name": "US",
    "organization_name": "DigiCert Inc",
    "organizational_unit_name": "www.digicert.com"
}

sha256 = reorder_issuer_and_sha256(issuer)
print("SHA256:", sha256)

print(get_sha256_hex_from_str('{"common_name": "RapidSSL TLS RSA CA G1", "country_name": "US", "organization_name": "DigiCert Inc", "organizational_unit_name": "www.digicert.com"}'))

import numpy as np
import matplotlib.pyplot as plt
import math

def generate_spiral_coords_ccw_from_top_left(n):
    """
    逆时针螺旋，从左上角开始，生成 n 个点的坐标 (x,y)
    """
    M = math.ceil(math.sqrt(n))
    grid = -np.ones((M, M), dtype=int)
    # 逆时针方向：下，右，上，左
    directions = [(1,0), (0,1), (-1,0), (0,-1)]
    dir_idx = 0
    x, y = 0, 0
    coords = []
    for i in range(n):
        coords.append((x, y))
        grid[x,y] = i
        dx, dy = directions[dir_idx]
        nx, ny = x + dx, y + dy
        if nx<0 or nx>=M or ny<0 or ny>=M or grid[nx, ny] != -1:
            dir_idx = (dir_idx + 1) % 4
            dx, dy = directions[dir_idx]
            nx, ny = x + dx, y + dy
        x, y = nx, ny
    return coords, M

# 你的数据，举例已排序从最大到最小
values = [
    584514, 188557, 92969, 58662, 55127, 32024, 31852, 29625, 2252, 2131,
    17757, 1536, 15271, 870, 657, 666, 263, 96, 726, 40,
    30, 28, 19, 15, 13, 5, 3, 2, 1, 1
]

n = len(values)
coords, M = generate_spiral_coords_ccw_from_top_left(n)

fig, ax = plt.subplots(figsize=(8,8))
ax.set_aspect('equal')

vals = np.array(values)
norm = plt.Normalize(vmin=vals.min(), vmax=vals.max())
cmap = plt.cm.viridis_r  # 反转颜色，最大值颜色更深

for (x,y), val in zip(coords, values):
    color = cmap(norm(val))
    square = plt.Rectangle((y, M-1 - x), 1, 1, facecolor=color, edgecolor='gray')
    ax.add_patch(square)

sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
sm.set_array([])
plt.colorbar(sm, ax=ax, fraction=0.046, pad=0.04, label='Value')

ax.set_xticks([])
ax.set_yticks([])
ax.set_xlim(-0.5, M-0.5)
ax.set_ylim(-0.5, M-0.5)
plt.title('Square Spiral Plot (Counterclockwise from top-left)')
plt.savefig("test.png")
