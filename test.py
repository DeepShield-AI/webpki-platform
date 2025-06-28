import pymysql
conn = pymysql.connect(
    host="127.0.0.1",
    port=3306,
    user="tianyu",
    password="123456",
    db="cert"
)
print("✅ pymysql raw connect success")