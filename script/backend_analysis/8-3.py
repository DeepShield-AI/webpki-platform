
import json

with open('8-fp_out.json', 'r') as f:
    data = json.load(f)

total = 0
for r_key, sha_dict in data.items():
    num_sha = len(sha_dict)
    total_count = sum(sha_dict.values())
    total += total_count
    print(num_sha)

print(total)
