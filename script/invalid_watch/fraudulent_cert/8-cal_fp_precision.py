
import json

with open("12-fp.json", "r") as f:
    my_dict = json.load(f)

# with open("trust_ca_common_name.txt", "r") as f:
    # my_dict = json.load(f)

result = {}
for ca, data in my_dict.items():

    normal = set(data['0'])
    forged = set(data['1'])

    if not normal:
        print(f"CA {ca} has no normal cert, pass")
        continue
    if not forged:
        print(f"CA {ca} has no forged cert, pass")
        continue

    # forged 和 normal 的交集
    overlap = forged & normal

    collision_rate = len(overlap) / len(forged) if forged else 0
    precision = 1 - collision_rate
    try:
        print(f"{json.loads(ca)["common_name"]}, {precision}")
    except:
        print(f"{json.loads(ca)["organization_name"]}, {precision}")
