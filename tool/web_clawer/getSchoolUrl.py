
import requests
from bs4 import BeautifulSoup
import mysql.connector
from mysql.connector import errorcode
import ssl
import socket


class row:

    def __init__(self, name, domain, city, cert) -> None:
        self.name = name
        self.domain = domain
        self.city = city
        self.cert = cert


def main():

    cnx = connectSQL()
    cursor = connectDB(cnx, "tlsDB")

    url = f"https://www.eol.cn/e_html/zt/mxdh/index.shtml"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

    # response type is str
    # response.content type is bytes
    # We need response.content since there are Chinese characters in the response
    soup = BeautifulSoup(response.content, 'html.parser')
    city_list = soup.find_all("div", class_ = "cityitem")

    for city in city_list:
        city_name = city.find("div", class_ = "cityname").text
        college_list = city.find_all("div", class_ = "school-li clearfix")

        for college in college_list:
            href_list = college.find_all("a")
            school_name = href_list[0].text
            index_domain = retriveDomain(href_list[0].get('href'))
            # admission_domain = retriveDomain(href_list[1].get('href'))

            index_cert = get_certificate(index_domain)
            # admission_cert = get_certificate(admission_domain)

            index_row = row(school_name, index_domain, city_name, index_cert)
            # admission_row = row(school_name, admission_domain, city_name, admission_cert)

            print(index_row.cert)
            # print(admission_row.cert)

            insert(cnx, "schoolIndexWeb", index_row)
            # insert(cnx, "", admission_row)

    cursor.close()
    cnx.close()


def retriveDomain(url):
    url_parts = url.split("/")
    return url_parts[2]


def connectSQL():
    try:
        # 设置数据库连接参数
        config = {
            "host": "localhost",
            "user": "root",
            "password": "GF_Game_Maker_ff0",
            "database": "tlsDB"
        }

        # 连接到数据库
        connection = mysql.connector.connect(**config)
        return connection

    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        connection.close()
        exit(0)


def connectDB(connection, db):
    try:
        cursor = connection.cursor()
        cursor.execute(f"USE {db}")
        return cursor

    except mysql.connector.Error as err:
        print("Error:", err)
        connection.close()
        exit(0)


def get_certificate(url):
    # url = url[7:]
    # url = "www.tsinghua.edu.cn"
    print(url)
    try:
        context = ssl.create_default_context()
        # Do not check cert right now
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((url, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                ssock.settimeout(2)
                cert = ssock.getpeercert(True)
                ssock.close()
                sock.close()
                return ssl.DER_cert_to_PEM_cert(cert)
                
    except TimeoutError:
        print("Connection with https failed, the web has no cert...")
        return None
    
    except Exception as e:
        print(e)
        return None


def insert(connection, table_name, row):
    try:
        cursor = connection.cursor()
        insert_query = (f"INSERT INTO {table_name} "
                        "(schoolname, domain, city, cert) "
                        "VALUES (%s, %s, %s, %s)")

        data = (row.name, row.domain, row.city, row.cert)
        cursor.execute(insert_query, data)
        connection.commit()  # 提交事务

    except mysql.connector.Error as err:
        print("Error:", err)


if __name__ == "__main__":
    main()
