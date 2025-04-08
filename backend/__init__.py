from flask import Flask, render_template
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from backend.config.flask_config import flask_config
from flask_login import LoginManager
import flask_excel as excel
from flask_cors import CORS

import os
import json, base64
from datetime import datetime, date
from flask.json.provider import DefaultJSONProvider

class CustomJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        # if isinstance(obj, datetime):
        #     return obj.isoformat()  # 或者用 obj.strftime("%Y-%m-%d %H:%M:%S") 等其他格式
        # else:
        #     return JSONEncoder.default(self, obj)
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')  # 将 bytes 转换为 Base64 编码的字符串
        if isinstance(obj, bytearray):
            return base64.b64encode(obj).decode('utf-8')
        raise TypeError(f"Type {type(obj)} not serializable")

loginmanager = LoginManager()
loginmanager.session_protection = 'strong'
#loginmanager.login_view = 'base.login'

moment = Moment()
db = SQLAlchemy()

def create_app(config_name):
    app = Flask(__name__, template_folder=r"..\ui\templates", static_folder=r"..\ui\static")
    CORS(app, resources={r"/api/*": {"origins": ["http://localhost:8080", "http://118.229.43.254:4080"]}})
    # CORS(app)
    # CORS(app, origins="http://118.229.43.254:4080")
    #  替换默认的json编码器
    app.json = CustomJSONProvider(app)
    app.config.from_object(flask_config[config_name])
    flask_config[config_name].init_app(app)

    moment.init_app(app)
    db.init_app(app)
    loginmanager.init_app(app)
    excel.init_excel(app)
    return app

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
from .blueprint import base as base_blueprint
app.register_blueprint(base_blueprint)
