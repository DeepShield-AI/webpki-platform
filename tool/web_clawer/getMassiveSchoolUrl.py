
import requests
from bs4 import BeautifulSoup
import mysql.connector
from mysql.connector import errorcode
from time import sleep

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class SchoolInfo:

    def __init__(self, name:str, location:str, tags:list[str], urls:list[str]) -> None:
        self.name = name
        self.location = location
        self.tags = tags
        self.urls = urls

    def insertIntoTable(self, connection:mysql.connector.MySQLConnection, table_name:str):
        try:
            cursor = connection.cursor()

            # Multiple tags and urls are seperated by semi-colon
            insert_tag = ";".join(self.tags)
            insert_url = ";".join(self.urls)
            insert_query = (f"INSERT INTO {table_name} "
                            "(schoolname, location, tags, urls, cert) "
                            "VALUES (%s, %s, %s, %s, %s)")

            data = (self.name, self.location, insert_tag, insert_url, None)
            cursor.execute(insert_query, data)
            connection.commit()

        except mysql.connector.Error as err:
            print("Error:", err)


def retriveDomain(url):
    url_parts = url.split("/")
    return url_parts[2]


def connectSQL():
    try:
        # 设置数据库连接参数
        config = {
            "host": "localhost",
            "user": "tianyu",
            "password": "Password@123",
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


def connectDB(connection:mysql.connector.MySQLConnection, db:str):
    try:
        cursor = connection.cursor()
        cursor.execute(f"USE {db}")
        return cursor

    except mysql.connector.Error as err:
        print("Error:", err)
        connection.close()
        exit(0)


def main():

    logfile = "log.txt"
    logger = open(logfile, "w")

    cnx = connectSQL()
    cursor = connectDB(cnx, "tlsDB")

    url_base = f"https://www.gaokao.cn/school/"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}

    chrome_options = Options()
    chrome_options.add_argument('--headless')  # 无头模式，可选
    chrome_options.add_argument('--disable-gpu')  # 禁用GPU加速，可选
    chrome_options.add_argument("--blink-settings=imagesEnabled=false") # 禁止图片加载
    chrome_options.add_argument('--window-size=800x600')  # 设置浏览器窗口大小，可选
    chrome_options.add_argument('lang=zh_CN.UTF-8')
    #修改windows.navigator.webdriver，防机器人识别机制，selenium自动登陆判别机制
    chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])

    driver = webdriver.Chrome(options = chrome_options)

    # After manually observe, the index number does not exceed 4000
    n = 3257
    while n < 4000:
        n += 1
        url = url_base + str(n)
        print(f"Retrieving {url}...")

        try:
            # Wait until the web is fully loaded
            driver.get(url)
            sleep(0.2)
            wait = WebDriverWait(driver, 10)
            wait.until(EC.presence_of_element_located((By.TAG_NAME, "title")))
            wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            tab_title = driver.title
            print(tab_title)

            # If the driver does not load anything, retry
            if not tab_title:
                logger.write(f"Retry {url}...\n")
                n -= 1
                continue

            # The web gaokao.cn applies dynamic request handler
            if "2024高考志愿填报服务平台" in tab_title:
                logger.write(f"URL with number {n} redirects to the index page...\n")
                # sleep(2)
                continue
            
            page_source = driver.page_source
            soup = BeautifulSoup(page_source, 'html.parser')

            # response = requests.get(url, headers=headers)
            # response.raise_for_status()
            # soup = BeautifulSoup(response.content, 'html.parser')
            # print(soup)

            if not soup:
                logger.write(f"{url} is not fully loaded...\n")
                continue

            school_info = soup.find("div", class_ = "schoolName clearfix school_view_top")

            if not school_info:
                logger.write(f"URL with number {n} does not have any school content...\n")
                continue

            school_name = school_info.find("span", class_ = "line1-schoolName").text
            school_location = school_info.find("span", class_ = "line1-province").text
            school_tags = school_info.find_all("div", class_ = "line2_item")

            school_tag_list = []
            for tag in school_tags:
                school_tag_list.append(tag.text)

            school_url_list = []
            school_urls = school_info.find("span", class_ = "school-info-label").find_all("a")
            for u in school_urls:
                school_url_list.append(u.text)

            row = SchoolInfo(school_name, school_location, school_tag_list, school_url_list)
            print(row.tags, row.urls)
            row.insertIntoTable(cnx, "schoolIndexWeb3")

            logger.write(f"{url} writes successfully!\n")

        except Exception as e:
            print(f"An error occurred: {e}")
            # driver.quit()
            break

    driver.quit()
    cursor.close()
    cnx.close()
    logger.close()


if __name__ == "__main__":
    main()
