
import re
import json
from collections import defaultdict
from backend.celery.celery_db_pool import engine_cert

with open("9-fp_group.json", "r") as f:
    data = json.load(f)

issuer_out = open('9-issuer_precision.json', 'w')
spki_out = open('9-spki_precision.json', 'w')
issuer_name_group = defaultdict(int)
spki_group = defaultdict(int)
new_conn = engine_cert.raw_connection()
domain_pattern = re.compile(r"^(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$")

for fp, num in data.items():
    if num > 1:

        with new_conn.cursor() as cursor:
            query = """
                SELECT id from cert_fp
                WHERE cert_fp_sha256 = %s
            """
            cursor.execute(query, (fp,))
            rows = cursor.fetchall()

            if rows:
                for row in rows:
                    id = row[0]
                    query = """
                        SELECT issuer, spkisha256 from cert_search
                        WHERE id = %s
                    """
                    cursor.execute(query, (id,))
                    cert = cursor.fetchone()

                    if cert:
                        issuer = json.loads(cert[0])
                        if isinstance(issuer, str): continue
                        common_name = issuer.get('common_name')
                        if common_name and (domain_pattern.match(str(common_name)) or ip_pattern.match(str(common_name))):
                            continue
                        
                        organization_name = issuer.get('organization_name', None)
                        issuer_name_group[str(organization_name)] += 1

                        spki = cert[1]
                        spki_group[str(spki)] += 1

        json.dump(issuer_name_group, issuer_out)
        issuer_out.write('\n')
        json.dump(spki_group, spki_out)
        spki_out.write('\n')
        issuer_name_group = defaultdict(int)
        spki_group = defaultdict(int)

new_conn.close()
issuer_out.close()
spki_out.close()
