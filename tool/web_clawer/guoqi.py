
import requests
from bs4 import BeautifulSoup

def get_homepage_from_baidu(query):
    url = f"https://www.baidu.com/s?wd={query}"
    url = f"https://cn.bing.com/search?q={query}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')
    results = soup.find_all('div', class_='result')
    for result in results:
        link = result.find('a')
        if link:
            return link['href']

    return None

def main():
    with open('institution_list.txt', 'r') as file:
        institutions = file.readlines()

    for institution in institutions:
        institution = institution.strip()
        homepage = get_homepage_from_baidu(institution)
        if homepage:
            print(f"Institution: {institution}, Homepage: {homepage}")
        else:
            print(f"Homepage not found for: {institution}")

if __name__ == "__main__":
    main()

