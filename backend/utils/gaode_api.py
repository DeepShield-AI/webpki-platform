
import requests

# 高德地图API密钥
key = 'f82d8cb02218ff5405a005d48e2ed626'

def get_location_by_address(address, city):
    url = f"https://restapi.amap.com/v3/geocode/geo?key={key}&address={address}&city={city}"
    response = requests.get(url)
    data = response.json()
    return data

'''
data:
{
  "status": "1",
  "info": "OK",
  "infocode": "10000",
  "count": "1",
  "geocodes": [
    {
      "formatted_address": "北京市工业大学",
      "country": "中国",
      "province": "北京市",
      "citycode": "010",
      "city": "北京市",
      "district": "朝阳区",
      "township": [],
      "neighborhood": {
        "name": [],
        "type": []
      },
      "building": {
        "name": [],
        "type": []
      },
      "adcode": "110105",
      "street": [],
      "number": [],
      "location": "116.482125,39.877113",
      "level": "未知"
    }
  ]
}
'''
