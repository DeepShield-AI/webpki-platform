
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from time import sleep

# driver = webdriver.Firefox()
# driver.get("http://www.python.org")
# assert "Python" in driver.title
# elem = driver.find_element_by_name("q")
# elem.clear()
# elem.send_keys("pycon")
# elem.send_keys(Keys.RETURN)
# assert "No results found." not in driver.page_source
# driver.close()


# element = driver.find_element_by_xpath("//select[@name='name']")
# all_options = element.find_elements_by_tag_name("option")
# for option in all_options:
#     print("Value is: %s" % option.get_attribute("value"))
#     option.click()

# # Assume the button has the ID "submit" :)
# driver.find_element_by_id("submit").click()


def main():
    # 设置Chrome浏览器的首选项，指定文件的下载路径
    download_path = "C:\\Users\\17702\\Desktop\\Cert Database\\国务院有关部门"

    chrome_options = Options()
    # chrome_options.add_argument('--headless')  # 无头模式，可选
    chrome_options.add_argument('--disable-gpu')  # 禁用GPU加速，可选
    chrome_options.add_argument('--window-size=1920x1080')  # 设置浏览器窗口大小，可选
    chrome_options.add_experimental_option('prefs', {
        'download.default_directory': download_path,  # 设置默认下载路径
        'download.prompt_for_download': False,  # 禁止弹出下载提示框
        'download.directory_upgrade': True,
        'safebrowsing.enabled': True  # 启用安全浏览，可选
    })
    # chrome_options.add_experimental_option('prefs', {
    #     'download.default_directory': download_path,  # 设置默认下载路径
    # })

    # options.add_argument("download.default_directory=C:\\Music")
    # browser = webdriver.Firefox(options=options, executable_path=r'C:\\selenium\\geckodriver.exe')

    #修改windows.navigator.webdriver，防机器人识别机制，selenium自动登陆判别机制
    chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])

    # prefs = {'profile.default_content_settings.popups': 0, #防止保存弹窗
    # 'download.default_directory':tmp_path,#设置默认下载路径
    # "profile.default_content_setting_values.automatic_downloads":1#允许多文件下载
    # }
    # chrome_options.add_experimental_option('prefs', prefs)

    # 创建浏览器驱动，这里使用Chrome浏览器驱动
    driver = webdriver.Chrome(options = chrome_options)

    try:
        driver.get("https://zfwzxx.www.gov.cn/check_web/databaseInfo/download#page-4")

        # <div class="dpage_btn dpage_btn_click active" id="bwmh" 
        # onclick="_trackData.push(['addaction','全国政府网站基本信息数据库', '部委门户'])">部委门户</div>
        # ulist = driver.find_element_by_xpath("//ul[@id='dpageUl']")
        ulist = driver.find_element(By.XPATH, "//ul[@id='dpageUl']")
        # print("Value is: %s" % ulist.get_attribute("class"))

        # Simulate click and download
        # list_items = ulist.find_elements(By.CLASS_NAME, "dpage_btn dpage_btn_click")
        button_elements = driver.find_elements(By.XPATH, "//div[@class='dpage_btn dpage_btn_click']")
        # button_elements = driver.find_element(By.XPATH, "//div[@class='dpage_btn dpage_btn_click' and @id='bwmh']")
        print(len(button_elements))

        download_link = driver.find_element(By.XPATH, "//div[@class='btn_down']")
        # print(download_link.get_attribute("onclick"))

        i = 0
        while i < len(button_elements):
            print(i)

            try:
                button_elements[i].click()
                button_id = button_elements[i].get_attribute("id")
                print(button_id)
            except:
                # <a href="#page-2" class="page-link next">下一页</a>
                next_page = driver.find_element(By.XPATH, "//a[@class='page-link next']")
                next_page.click()
                continue

            download_link.click()
            print("Downloading...")
            sleep(2)

            # driver.refresh()
            # sleep(2)

            # Cancel the list
            # <li id="bwmh_unit"><div class="district_bor">部委门户<i></i></div></li>
            # element.style {
            # }
            # .district_bor i {
            #     background: url(../images/del.jpg) 0 0 no-repeat;
            #     width: 13px;
            #     height: 13px;
            #     cursor: pointer;
            #     float: right;
            #     margin: 2px 2px 0 0;
            # }

            # 使用CSS选择器定位<i>标签，通过背景图像和浮动位置来找到关闭图标
            # Code
            # <input type="image" src="/images/btn_next.png">
            # CSS
            # input[type="image" i] 
            # {
            #     cursor: pointer;
            # }
            # WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "input[src='/images/btn_next.png'][type='image']"))).click()
            # close_icon = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.CSS_SELECTOR, ".district_bor i[url='../images/del.jpg']")))
            # print(close_icon)
            # close_icon.click()

            cancel_element_id = button_id + "_unit"
            cancel_element_xpath = "//li[@id='" + cancel_element_id + "']"
            print(cancel_element_xpath)

            cancel_element = driver.find_element(By.XPATH, cancel_element_xpath)
            cancel_button = cancel_element.find_element(By.XPATH, "//div[@class='district_bor']").find_element(By.TAG_NAME, "i")
            # cancel_button = cancel_element.find_element(By.XPATH, "//i")
            cancel_button.click()
            sleep(2)
            i += 1


    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        driver.quit()
        pass
    
if __name__ == "__main__":
    main()
