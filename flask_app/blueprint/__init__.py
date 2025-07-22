
import os
from flask import Blueprint
from dotenv import load_dotenv

dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.env'))
print("Loading dotenv from:", dotenv_path)

if not os.path.exists(dotenv_path):
    raise RuntimeError(f".env file not found at {dotenv_path}")

load_dotenv(dotenv_path=dotenv_path, override=True)

URL_PREFIX = os.getenv('URL_PREFIX').strip()
print("Loaded URL_PREFIX:", repr(URL_PREFIX))

base = Blueprint('base', __name__, url_prefix=URL_PREFIX)

from flask_app.routes import *
