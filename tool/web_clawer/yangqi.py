
import requests
from bs4 import BeautifulSoup
import re

def main():

    url = f"http://www.sasac.gov.cn/n2588045/n27271785/n27271792/c14159097/content.html#:~:text=%E5%A4%AE%E4%BC%81%E5%90%8D%E5%BD%95%EF%BC%8D%E5%9B%BD%E5%8A%A1%E9%99%A2%E5%9B%BD%E6%9C%89%E8%B5%84%E4%BA%A7%E7%9B%91%E7%9D%A3%E7%AE%A1%E7%90%86%E5%A7%94%E5%91%98%E4%BC%9A%20%E9%A6%96%E9%A1%B5%20%3E%20%E5%9C%A8%E7%BA%BF%E6%9C%8D%E5%8A%A1%20%3E,%E5%A4%AE%E4%BC%81%E4%BF%A1%E6%81%AF%E6%9F%A5%E8%AF%A2%20%3E%20%E5%A4%AE%E4%BC%81%E5%90%8D%E5%BD%95%20%3E%20%E6%AD%A3%E6%96%87"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

    # 从响应头中获取网页编码
    # charset = re.search(r'charset=([\w-]+)', response.headers.get('Content-Type', '')).group(1)

    # 使用网页编码来解码网页内容
    # html_content = response.content.decode(charset)

    # 创建一个BeautifulSoup对象，并指定解析器为html.parser，并指定编码
    # soup = BeautifulSoup(html_content, 'html.parser', from_encoding=charset)
    
    # 获取网页的HTML内容，并根据响应头指定的编码进行解码
    # html_content = response.content.decode(response.encoding)
    # print(html_content)

    # 创建一个BeautifulSoup对象，并指定解析器为html.parser，并指定编码
    # soup = BeautifulSoup(html_content, 'html.parser', from_encoding=response.encoding)

    soup = BeautifulSoup(response.content, 'html.parser')
    element_list = soup.find_all('td', align = "left")
    print(len(element_list))

    output_file_dir = "C:\\Users\\17702\\Desktop\\Cert Database\\国有企业\\央企\\tls_table.txt"
    
    with open(output_file_dir, 'w', encoding='utf-8') as file:
        for element in element_list:
            a = element.find('a')
            href = a.get('href')
            name = a.text
            file.write("{},{}\n".format(href, name))
            print("{},{}\n".format(href, name))

if __name__ == "__main__":
    main()
