
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def find_paragraph_with_text(soup, target_text):
    return soup.find(lambda tag: tag.name == 'p' and target_text in tag.get_text())


def save_image(img, save_dir):
    img_url = img.get('src')
    print(img_url)

    if img_url:
        # img_url = urljoin(url, img_url)  # 构建完整的图片URL
        try:
            img_response = requests.get(img_url)
            img_response.raise_for_status()  # 检查是否请求成功
        except requests.exceptions.RequestException as e:
            print(f"Img occurr failed: {e}")
            return
        
        # 获取图片数据并保存到本地文件
        img_data = img_response.content
        img_filename = os.path.join(save_dir, os.path.basename(img_url))
        print(img_filename)

        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        with open(img_filename, 'wb') as img_file:
            img_file.write(img_data)
            print(f"Saved image: {img_filename}")


if __name__ == "__main__":
    target_url = "https://www.sohu.com/a/670663103_121124359"  # 请将此处的URL替换为目标网页的地址
    # target_text = str("分行业及其上市子公司".encode('utf-8'))
    target_text = "分行业及其上市子公司"
    
    try:
        response = requests.get(target_url)
        response.raise_for_status()  # 检查是否请求成功
        soup = BeautifulSoup(response.text, 'html.parser')

        # paras = soup.find_all("p")
        # for p in paras:
        #     print(p.text)
        #     print(target_text in p.text)

    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")

    target_paragraph = find_paragraph_with_text(soup, target_text)
    print(target_paragraph.text)

    pre_dir = "C:\\Users\\17702\\Desktop\\Cert Database\\国有企业\\央企"
    sub_dir = ""
    next_paragraph = target_paragraph

    while True:
        next_paragraph = next_paragraph.find_next('p')
        print(next_paragraph)

        if next_paragraph.get("data-role") == "editor-name":
            break
        # print(next_paragraph.text)
        if not next_paragraph.text == "":
            sub_dir = next_paragraph.text
            # print(sub_dir)
        else:
            # print("img")
            img = next_paragraph.find('img')
            save_dir = os.path.join(pre_dir, sub_dir)
            # print(img)
            save_image(img, save_dir)

