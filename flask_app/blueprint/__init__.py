
import os
from flask import Blueprint
from dotenv import load_dotenv
load_dotenv()  # 默认会加载 .env 文件

URL_PREFIX = os.getenv('URL_PREFIX', '')
base = Blueprint('base', __name__, url_prefix=URL_PREFIX)

from flask_app.routes import *
