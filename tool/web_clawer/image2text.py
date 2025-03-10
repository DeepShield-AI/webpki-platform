import pytesseract
from PIL import Image

# If you don't have tesseract executable in your PATH, include the following:
pytesseract.pytesseract.tesseract_cmd = r'D:\Tesseract-OCR\tesseract'
# Example tesseract_cmd = r'C:\Program Files (x86)\Tesseract-OCR\tesseract'

# 设置Tesseract识别语言为中文（简体）
custom_config = r'--oem 3 --psm 6 -l chi_sim'

# 使用Tesseract识别图片文字


home_dir = r"C:\Users\17702\Desktop\Cert Database\国有企业\央企"
image = Image.open(r'C:\Users\17702\Desktop\Cert Database\国有企业\央企\一、能源电力\0c61922f9b534df593866d76966d29e5.png')
text = pytesseract.image_to_string(image, config = custom_config)

# 打印识别的文字
print(text)
