import os
import time
import datetime
import hashlib
import shutil
import colorama
import json
import re
import requests
import pyotp
import qrcode
from ruamel.std.zipfile import delete_from_zip_file
from pathlib import Path
from random import randint, choice
from flask import Flask, render_template, url_for, send_from_directory, request, redirect, session, abort, send_file
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from flask_mail import Message, Mail

# Установление основным файлом по работе с фраемворком app.py
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = "d83b67fd90a30ab654924763d4381e352428bffcade39f057682fe2b02e6aae0"
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=2)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['RECAPTCHA_PUBLIC_KEY'] = "6Ld74-oUAAAAAJC0UOY6PtrOrNcxQ2VQCfGAqBOC"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6Ld74-oUAAAAAD2_Jl2IVKh2uCCI9OPX_7oTdLz4"
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'voidtrainer2251@gmail.com'  # введите свой адрес электронной почты здесь
app.config['MAIL_DEFAULT_SENDER'] = 'voidtrainer2251@gmail.com'  # и здесь
app.config['MAIL_PASSWORD'] = 'prpbzcocgasmaniy'  # введите пароль vfsf7891 #GeG-2yw-g77-P5a
app.config['UPLOAD_FOLDER'] = 'static/users'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
app.config['MAX_CONTENT_LENGTH'] = 8 * (1024 ** 3)

db = SQLAlchemy(app)
mail = Mail(app)
rest_key = "dfgh742684"
rest_key_hash = "ed1487cd8052d2d0385da5facd6d1d7c7e995803d2165dc5460fab099ca0a518"
main_rest_ip = "http://127.0.0.1:5000/"
image_types = ('.jpg', '.png', '.bmp')
main_url = "http://127.0.0.1:5000/"

# from app import app, db
# app.app_context().push()
# db.create_all()

# подключаем CSS-фраемворк bootstrap
bootstrap = Bootstrap(app)


# Создание ORM-модели базы данных аутентификации
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    _2fa = db.Column(db.Boolean, default=False)
    size_gb = db.Column(db.Integer, default=15)
    phone_number = db.Column(db.String(10))
    register_time = db.Column(db.DateTime(), default=datetime.datetime.utcnow())
    reserve_code = db.Column(db.String(80), default="")
    google_key = db.Column(db.String(64), default="")

    def __repr__(self):
        return "<id={};username={}>".format(self.id, self.username)


# Добавляем капчу
class ReCaptha(FlaskForm):
    captha = RecaptchaField()


# установка времени session
@app.before_request
def make_session_permanent():
    session.modified = True
    session.permanent = True


# Обработка ошибки 403
@app.errorhandler(403)
def error_403(err):
    data = {
        "title": "Доступ запрещён",
        "caption_text": "Ошибка 403",
        "error_text": "Доступ к данной ссылке запрещён!"
    }
    print(colorama.Fore.RED + str(err))
    return render_template("error.html", data=data)


# Обработка ошибки 404
@app.errorhandler(404)
def error_404(err):
    data = {
        "title": "Страница не найдена",
        "caption_text": "Ошибка 404",
        "error_text": "Данная страница не найдена на сайте! Если вы считаете это ошибкой, обратитесь к администрации!"
    }
    print(colorama.Fore.RED + str(err))
    return render_template("error.html", data=data)


# Обработка ошибки 413
@app.errorhandler(413)
def error_413(err):
    data = {
        "title": "Слишком большой запрос",
        "caption_text": "Ошибка 413",
        "error_text": "Загружен слишком большой файл или слишком много файлов!"
    }
    print(colorama.Fore.RED + str(err))
    return render_template("error.html", data=data)


# Подключаем иконку сайта
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'img/infinity.png', mimetype='image/vnd.microsoft.icon')


# Используем rest api в работе с таблицей пользователей
@app.route('/user', methods=['GET', 'POST'])
@app.route('/user/<int:get_id>', methods=['GET', 'PUT', 'DELETE'])
def user(get_id=None):
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    if request.method == 'GET':
        if get_id is None and "filter_email" not in request.json.keys():
            users = {'users': []}
            data = User.query.all()
            for i in data:
                users['users'].append(requests.get(f"{main_rest_ip}user/{i.id}", json={"rest_key": rest_key},
                                                   headers={'Content-type': 'application/json'}).json())
            return users
        elif "filter_email" in request.json.keys():
            data = User.query.filter_by(email=request.json["filter_email"]).first()
        else:
            data = User.query.filter_by(id=get_id).first()
        return {'id': data.id, 'username': data.username, 'password_hash': data.password_hash,
                'email': data.email, 'phone_number': data.phone_number, 'size_gb': data.size_gb,
                '_2fa': data._2fa, 'register_time': data.register_time,
                'reserve_code': data.reserve_code, 'google_key': data.google_key}
    elif request.method == 'POST':
        username = request.json['username']
        password_hash = request.json['password_hash']
        email = request.json['email']
        phone_number = request.json['phone_number']
        get_user = User(username=username, email=email, password_hash=password_hash, phone_number=phone_number)
        db.session.add(get_user)
        db.session.commit()
        return {"message": "вы успешно зарегестрированы"}
    elif request.method == 'PUT':
        data = User.query.get(get_id)
        if "username" in request.json.keys():
            data.username = request.json["username"]
        if "password_hash" in request.json.keys():
            data.password_hash = request.json["password_hash"]
        if "email" in request.json.keys():
            data.email = request.json["email"]
        if "phone_number" in request.json.keys():
            data.phone_number = request.json["phone_number"]
        if "size_gb" in request.json.keys():
            data.size_gb = request.json["size_gb"]
        if "_2fa" in request.json.keys():
            data._2fa = request.json["_2fa"]
        if "reserve_code" in request.json.keys():
            data.reserve_code = request.json["reserve_code"]
        if "google_key" in request.json.keys():
            data.google_key = request.json["google_key"]
        db.session.commit()
        return {"message": "данные успешно изменены!"}
    elif request.method == 'DELETE':
        user = User.query.get_or_404(get_id)
        db.session.delete(user)
        db.session.commit()
        shutil.rmtree(f"static/users/{get_id}")
        with open("static/users/check_and_download.json", 'r+') as cad:
            json_data = json.load(cad)
            cad.seek(0)
            del_keys = []
            for get_key in json_data.keys():
                if re.split("/|\\\\", get_key)[0] == str(get_id):
                    del_keys.append(get_key)
            for i in del_keys:
                del json_data[i]
            json.dump(json_data, cad)
            cad.truncate()
        for users_id in os.listdir("static/users"):
            if os.path.isdir(f"static/users/{users_id}"):
                with open(f"static/users/{users_id}/file_access.json", 'r+') as fa:
                    json_data = json.load(fa)
                    fa.seek(0)
                    for private_obj in json_data["private_objects"]:
                        for p_user in private_obj['users']:
                            if int(p_user['id']) == int(get_id):
                                private_obj['users'].remove(p_user)
                                json_data["private_objects"][
                                    json_data["private_objects"].index(private_obj)] = private_obj
                    json.dump(json_data, fa)
                    fa.truncate()
                with open(f"static/users/{users_id}/check_files.json", 'r+') as cf:
                    json_data = json.load(cf)
                    cf.seek(0)
                    for checked in json_data:
                        if re.split("/|\\\\", checked)[0] == str(get_id):
                            json_data.remove(checked)
                    json.dump(json_data, cf)
                    cf.truncate()
        return {"message": "пользователь успешно удалён!"}


# Обработка email-писем
@app.route("/email", methods=['POST'])
def send_email():
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    msg = Message("Void Trainer", recipients=[request.json['email']])
    if 'new_password' in request.json.keys():
        msg.html = f"<h1>Новый пароль</h1><p>Ваш новый пароль в" \
                   f" <strong>Void Trainer</strong>: {request.json['new_password']}</p>"
    else:
        msg.html = f"<h1>Подтверждение почты</h1><p>Ваш проверочный код для авторизации в" \
                   f" <strong>Void Trainer</strong>: {request.json['code']}</p>"
    mail.send(msg)
    return {"message": "Сообщение успешно отправлено"}


# Обработка sms-писем
@app.route("/sms", methods=['POST'])
def sms():
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    url = 'https://api.httpsms.com/v1/messages/send'

    headers = {
        'x-api-key': "nirTxrKMB9NY9oB0zP2wqY2DTE-xhLM7D-wic8fV755hi-u7mm3GXcmEF80Ol1jK",
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    payload = {
        "content": f"Ваш код подтверждения Voidtainer: {request.json['code']}",
        "from": "+79124568482",
        "to": f"+{request.json['phone_number']}"
    }

    requests.post(url, headers=headers, data=json.dumps(payload))
    return {"message": "Сообщение успешно отправлено!"}


# Обработка Google Authenicator
@app.route("/google_auth/<int:get_id>", methods=['POST', 'GET'])
def google_auth(get_id):
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    if request.method == 'GET':
        totp = pyotp.TOTP(request.json['google_key'])
        return {"verify": totp.verify(request.json['code'])}
    elif request.method == 'POST':
        key = pyotp.random_base32()

        totp_auth = pyotp.totp.TOTP(
            key).provisioning_uri(
            name=f'{get_id}',
            issuer_name='VoidTainer')
        qrcode.make(totp_auth).save(f"static/qr_auth{get_id}.png")
        return {"key": key}


# Выводим сколько памяти осталось у пользователя
@app.route('/progress/<int:get_id>', methods=['GET'])
def progress(get_id):
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    edes = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"]
    get_progress = {}
    user = requests.get(f"{main_rest_ip}user/{get_id}", json={"rest_key": rest_key},
                        headers={'Content-type': 'application/json'}).json()
    used = 0
    for root, dirs, files in os.walk(f'static/users/{get_id}/files'):
        for name in files:
            used += os.path.getsize(os.path.join(root, name))
    for root, dirs, files in os.walk(f'static/users/{get_id}/trash'):
        for name in files:
            used += os.path.getsize(os.path.join(root, name))
    get_progress['used_bytes'] = used
    user_dels = 0
    max_size = user['size_gb']
    get_progress['max_bytes'] = int(max_size * (1024 ** 3))
    get_progress['value'] = used / (max_size * (1024 ** 3))
    for get_del in range(5):
        if used // 1024 > 0:
            user_dels += 1
            used /= 1024
        else:
            break
    get_progress['used'] = round(used, 2)
    get_progress['used_ed'] = edes[user_dels]
    user_dels = 3
    for get_del in range(2):
        if max_size // 1024 > 0:
            user_dels += 1
            max_size /= 1024
        else:
            break
    get_progress['max'] = round(max_size, 2)
    get_progress['max_ed'] = edes[user_dels]

    return get_progress


# Получаем информацию о файле
@app.route('/file_info', methods=['GET'])
def file_info():
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    get_file = request.json['get_file']
    user_id = request.json['user_id']
    my_file = {"name": get_file.split("/")[-1], "full_size": 0, "path_name": f"{user_id}/{get_file}",
               "full_update_time": os.path.getmtime(f"static/users/{user_id}/{get_file}"), "private": True}
    if os.path.isdir(f"static/users/{user_id}/{get_file}"):
        my_file['obj_type'] = 'dir'
        for root, dirs, files in os.walk(f"static/users/{user_id}/{get_file}"):
            for name in files:
                my_file['full_size'] += os.path.getsize(f"{root}/{name}")
    else:
        my_file['obj_type'] = 'file'
        my_file['full_size'] = os.path.getsize(f"static/users/{user_id}/{get_file}")
    with open(f"static/users/{user_id}/file_access.json", 'r') as fa:
        json_data = json.load(fa)
        for json_file in json_data['open_objects']:
            if json_file['filename'] == f"{user_id}/{get_file}":
                my_file['private'] = False
        my_file["autonomous"] = f"{user_id}/{get_file}" in json_data['access_autonomous']
    edes = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ']
    dels = 0
    size = my_file['full_size']
    while size // 1024 > 0:
        size /= 1024
        dels += 1
    date = datetime.datetime.fromtimestamp(my_file['full_update_time'])
    my_file['update_time'] = {"date": date.strftime('%d.%m.%Y'), "time": date.strftime('%H:%M')}
    my_file['size'] = round(size, 2)
    my_file['size_ed'] = edes[dels]
    my_file['owner_id'] = user_id
    my_file['owner_username'] = requests.get(f"{main_rest_ip}user/{user_id}", json={"rest_key": rest_key},
                                             headers={'Content-type': 'application/json'}).json()['username']
    my_file['finded'] = False
    return my_file


# Проверка доступен  ли файл пользователю
@app.route('/file_access', methods=['GET'])
def file_access():
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    get_access = False
    read_only = True
    is_private = True
    public_read = True
    he_private = False
    r_user = request.json['owner_id']
    with open(f"static/users/{r_user}/file_access.json", 'r') as access_f:
        json_data = json.load(access_f)
        for open_obj in json_data["open_objects"]:
            if open_obj["filename"] == request.json['create_path']:
                get_access = True
                is_private = False
                public_read = open_obj["readOnly"]
                read_only = open_obj["readOnly"]
        for priv_obj in json_data["private_objects"]:
            if priv_obj["filename"] == request.json['create_path']:
                for g_user in priv_obj['users']:
                    if g_user['id'] == request.json['user_id']:
                        get_access = True
                        if read_only:
                            read_only = g_user["readOnly"]
                        he_private = True
    if int(request.json['user_id']) == int(request.json['owner_id']):
        read_only = False
        get_access = True
        he_private = True
    return {"access": get_access, "readOnly": read_only, "private": is_private,
            "public_read": public_read, "he_private": he_private}


@app.route('/access_params', methods=['GET'])
def access_params():
    if not request.is_json or hashlib.sha256(request.json["rest_key"].encode('utf-8')).hexdigest() != rest_key_hash:
        abort(403)
    a_params = {"open_readOnly": True, "private_users": []}
    get_file = request.json["file"]
    get_id = request.json["id"]
    with open(f"static/users/{get_id}/file_access.json", 'r') as fa:
        json_data = json.load(fa)
        for open_obj in json_data["open_objects"]:
            if open_obj['filename'] == get_file:
                a_params["open_readOnly"] = open_obj["readOnly"]
        for priv_obj in json_data["private_objects"]:
            if priv_obj['filename'] == get_file:
                for priv_user in priv_obj["users"]:
                    a_params["private_users"].append({"id": priv_user['id'], "username":
                        requests.get(f"{main_rest_ip}user/{priv_user['id']}", json={"rest_key": rest_key},
                                     headers={'Content-type': 'application/json'}).json()['username'],
                                                      "readOnly": priv_user['readOnly']})
    return a_params


# Отслеживаем главную страницу сайта
@app.route('/', methods=['GET', 'POST'])
def index():
    if "download_file" in session.keys():
        session.pop("download_file", None)
    if "user_id" in session.keys() and not session.get("user_id") is None and session.get("user_id") > 0:
        return redirect("/main")
    if not ("2fa_user" not in session.keys() or session.get("2fa_user") is None):
        session.pop("2fa_user", None)
    recaptha = ReCaptha()
    data = {
        "title": "Главная страница",
        "load": True,
        "error": False,
        "error_message": "",
        "user_id": 0,
        "password": "",
        "_2fa": False
    }

    if request.method == 'POST':
        data['load'] = False
        data['error'] = True
        mail_in_bd = False
        users = requests.get(f"{main_rest_ip}user", json={"rest_key": rest_key},
                             headers={'Content-type': 'application/json'}).json()
        for i in users['users']:
            if request.form['email'] == i["email"]:
                mail_in_bd = True
                data['user_id'] = i['id']
                data['password'] = i['password_hash']
                data['_2fa'] = i['_2fa']
                break
        if not recaptha.validate_on_submit():
            data['error_message'] = "Подтвердите, что вы не робот!"
        elif not mail_in_bd:
            data['error_message'] = "Аккаунта с данной почтой не существует!"
        elif hashlib.sha256(request.form['password'].encode('utf-8')).hexdigest() != data['password']:
            data['error_message'] = "Неверный пароль!"
        else:
            data['error'] = False
            if data['_2fa']:
                session['2fa_user'] = {"user": requests.get(f"{main_rest_ip}user/{data['user_id']}",
                                                            json={"rest_key": rest_key},
                                                            headers={'Content-type': 'application/json'}).json(),
                                       "new_password": None,
                                       "data": None, "_method": "auth"}
                return redirect("/2fa_code")
            else:
                session['user_id'] = data['user_id']
                return redirect("/")
    return render_template("login.html", data=data, recaptha=recaptha)


# Отслеживаем страницу регистрации имеющую ссылку "/register"
@app.route('/register', methods=['GET', 'POST'])
def register():
    if "user_id" in session.keys() and not session.get("user_id") is None and session.get("user_id") > 0:
        return redirect("/main")
    if not ("2fa_user" not in session.keys() or session.get("2fa_user") is None):
        session.pop("2fa_user", None)
    recaptha = ReCaptha()
    data = {
        "title": "Регистрация",
        "error_message": "",
        "error": False,
        "user": "",
        "code": 0,
        "code_iteration": 0
    }
    if request.method == "POST":
        if "data" not in session.keys():
            username = request.form['login']
            email = request.form['email']
            password = request.form['password']
            valid_password = request.form['valid_password']
            phone_number = request.form['phone_number']
            data['error'] = True
            mail_in_bd = False
            users = requests.get(f"{main_rest_ip}user", json={"rest_key": rest_key},
                                 headers={'Content-type': 'application/json'}).json()
            for i in users['users']:
                if email == i["email"]:
                    mail_in_bd = True
                    break
            if username == "":
                data['error_message'] = "Отсутствует имя пользователя!"
            elif email == "":
                data['error_message'] = "Отсутствует электронная почта!"
            elif mail_in_bd:
                data['error_message'] = "Данная электронная почта уже используется!"
            elif password == "":
                data['error_message'] = "Отсутствует пароль!"
            elif password != valid_password:
                data['error_message'] = "Пароли не совпадают!"
            elif not recaptha.validate_on_submit():
                data['error_message'] = "Подтвердите, что вы не робот!"
            else:
                data['error'] = False
                password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

                data['user'] = {'rest_key': rest_key, 'username': username, 'password_hash': password_hash,
                                'email': email, 'phone_number': phone_number}
                data['code'] = randint(0, 999999)

                requests.post(f"{main_rest_ip}email", json={"rest_key": rest_key,
                                                            "email": data['user']['email'],
                                                            "code": data['code']},
                              headers={'Content-type': 'application/json'})

                session['data'] = data

                return render_template("register.html", data=data, recaptha=recaptha)
        else:
            code = request.form['code']
            data = session.get('data')
            if code == str(data['code']):
                requests.post(f"{main_rest_ip}user", json=data['user'], headers={'Content-type': 'application/json'})
                session['user_id'] = requests.get(f"{main_rest_ip}user",
                                                  json={'rest_key': rest_key, "filter_email": data['user']['email']},
                                                  headers={'Content-type': 'application/json'}).json()['id']
                session.pop('data', None)
            else:
                data['error'] = True
                if data["code_iteration"] >= 3:
                    data['error_message'] = "Слишком много попыток!\nВам на почту пришёл новый код подтверждения!"
                    data['code'] = randint(0, 999999)

                    requests.post(f"{main_rest_ip}email", json={"rest_key": rest_key, "email": data['user']['email'],
                                                                "code": data['code']},
                                  headers={'Content-type': 'application/json'})
                    data["code_iteration"] = 0
                else:
                    data['error_message'] = "Неверный проверочный код!"
                    data["code_iteration"] += 1

                return render_template("register.html", data=data, recaptha=recaptha)

            return redirect("/")
    else:
        session.pop("data", None)
    return render_template("register.html", data=data, recaptha=recaptha)


@app.route('/no_password', methods=['GET', 'POST'])
def no_password():
    if "user_id" in session.keys() and not session.get("user_id") is None and session.get("user_id") > 0:
        return redirect("/main")
    if not ("2fa_user" not in session.keys() or session.get("2fa_user") is None):
        session.pop("2fa_user", None)
    recaptha = ReCaptha()
    data = {
        "title": "Подтверждение почты",
        "caption_text": "Подтвердите свою электронную почту и вам придёт новый пароль",
        "error": False,
        "error_message": "",
        "code": 0,
        "code_iteration": 0,
        "email": "",
        "user_id": 0,
        "_2fa": False
    }
    if request.method == 'POST':
        if not recaptha.validate_on_submit() and session.get("email") is None:
            data['error'] = True
            data['error_message'] = "Подтвердите, что вы не робот!"
        elif session.get("email") is None:
            mail_in_bd = False
            users = requests.get(f"{main_rest_ip}user", json={"rest_key": rest_key},
                                 headers={'Content-type': 'application/json'}).json()
            for i in users['users']:
                if request.form['email'] == i["email"]:
                    mail_in_bd = True
                    data['user_id'] = i['id']
                    data['_2fa'] = i['_2fa']
                    break
            if not mail_in_bd:
                data['error'] = True
                data['error_message'] = "Аккаунта с данной почтой не существует!"
            else:
                data["email"] = request.form['email']
                data['code'] = randint(0, 999999)
                requests.post(f"{main_rest_ip}email", json={"rest_key": rest_key, "email": data['email'],
                                                            "code": data['code']},
                              headers={'Content-type': 'application/json'})
                data["code_iteration"] = 0
                session['email'] = data
        else:
            data = session['email']
            data['error'] = True
            if str(data['code']) == request.form['code']:

                new_password = ""
                for i in range(randint(8, 16)):
                    new_password += choice(list('1234567890abcdefghigklmnopqrstuvyxwzABCDEFGHIGKLMNOPQRSTUVYXWZ'))

                session.pop("email", None)
                if data['_2fa']:
                    session['2fa_user'] = {"user": requests.get(f"{main_rest_ip}user/{data['user_id']}",
                                                                json={"rest_key": rest_key},
                                                                headers={'Content-type': 'application/json'}).json(),
                                           "new_password": new_password, "data": None, "_method": "auth"}
                    return redirect("/2fa_code")
                else:
                    session['user_id'] = data['user_id']
                    requests.post(f"{main_rest_ip}email", json={"rest_key": rest_key, "email": data['email'],
                                                                "new_password": new_password, "code": -1},
                                  headers={'Content-type': 'application/json'})
                    requests.put(f"{main_rest_ip}user/{session['user_id']}",
                                 json={'rest_key': rest_key,
                                       "password_hash": hashlib.sha256(new_password.encode('utf-8')).hexdigest()},
                                 headers={'Content-type': 'application/json'})
                    return redirect("/")
            else:
                if data["code_iteration"] >= 3:
                    data['error_message'] = "Слишком много попыток!\nВам на почту пришёл новый код подтверждения!"
                    data['code'] = randint(0, 999999)

                    requests.post(f"{main_rest_ip}email", json={"rest_key": rest_key, "email": data['email'],
                                                                "code": data['code']},
                                  headers={'Content-type': 'application/json'})

                    data["code_iteration"] = 0
                else:
                    data['error_message'] = "Неверный проверочный код!"
                    data["code_iteration"] += 1
    else:

        session.pop("email", None)
    return render_template("verify_email.html", data=data, recaptha=recaptha)


@app.route('/main', methods=['GET', 'POST'])
def main():
    with open("static/users/removes.json", 'r+') as rems:
        json_data = json.load(rems)
        rems.seek(0)
        for i in json_data:
            if os.path.exists(i):
                os.remove(i)
            json_data.remove(i)
        json.dump(json_data, rems)
        rems.truncate()
    if "download_file" in session.keys():
        session.pop("download_file", None)
    if os.path.isfile(f"static/qr_auth{session.get('user_id')}.png"):
        os.remove(f"static/qr_auth{session.get('user_id')}.png")
    if os.path.isfile(f"static/users/{session.get('user_id')}/icon_.png"):
        os.remove(f"static/users/{session.get('user_id')}/icon_.png")
    if "user_id" not in session.keys() or session.get("user_id") is None or session.get("user_id") <= 0:
        return redirect("/")
    if not ("2fa_user" not in session.keys() or session.get("2fa_user") is None):
        session.pop("2fa_user", None)
    data = {"title": "Мой диск",
            "user": requests.get(f"{main_rest_ip}user/{session.get('user_id')}", json={"rest_key": rest_key},
                                 headers={'Content-type': 'application/json'}).json(),
            "default_icon": url_for('.static', filename="img/user.svg"),
            "progress": requests.get(f"{main_rest_ip}progress/{session.get('user_id')}", json={"rest_key": rest_key},
                                     headers={'Content-type': 'application/json'}).json(),
            "custom_caption": "Доступ",
            "linear": True,
            "order_by": "name",
            "order_up": False,
            "error": False,
            "rename": False,
            "error_message": "",
            "_method": "",
            "file_types": "all",
            "files": [],
            "find_key": "",
            "create_path": "",
            "selected_file": {},
            "access_param": {},
            "down_urls": {},
            "main_url": main_url,
            "access_fined_users": [],
            "access_fined": False,
            "access_fined_key": "",
            "version_file_path": ""
            }
    if not os.path.isdir(f"static/users/{data['user']['id']}/files"):
        os.makedirs(f"static/users/{data['user']['id']}/files")
    if not os.path.isdir(f"static/users/{data['user']['id']}/tmp"):
        os.makedirs(f"static/users/{data['user']['id']}/tmp")
    if not os.path.isdir(f"static/users/{data['user']['id']}/trash"):
        os.makedirs(f"static/users/{data['user']['id']}/trash")
    if not os.path.isfile(f"static/users/{data['user']['id']}/file_access.json"):
        with open(f"static/users/{data['user']['id']}/file_access.json", 'w') as fa:
            json.dump({"access_autonomous": [], "open_objects": [], "private_objects": []}, fa)
    if not os.path.isfile(f"static/users/{data['user']['id']}/check_files.json"):
        with open(f"static/users/{data['user']['id']}/check_files.json", 'w') as fa:
            json.dump([], fa)
    if not os.path.isfile(f"static/users/{data['user']['id']}/trash_time.json"):
        with open(f"static/users/{data['user']['id']}/trash_time.json", 'w') as fa:
            json.dump({}, fa)
    else:
        with open(f"static/users/{data['user']['id']}/trash_time.json", 'r+') as fa:
            json_data = json.load(fa)
            fa.seek(0)
            jd_keys = json_data.keys()
            for key in jd_keys:
                if json_data[key] > datetime.timedelta(days=30).total_seconds() + time.time():
                    if os.path.isfile(f"static/users/{data['user']['id']}/trash/{key}"):
                        os.remove(f"static/users/{data['user']['id']}/trash/{key}")
                    elif os.path.isfile(f"static/users/{data['user']['id']}/trash/{key}"):
                        shutil.rmtree(f"static/users/{data['user']['id']}/trash/{key}")
                    json_data.remove(key)
            json.dump(json_data, fa)
            fa.truncate()
    if "place" in session.keys() and session.get("place") is not None:
        data['linear'] = session.get('place')['linear']
        data['file_types'] = session.get('place')['file_types']
        data['order_by'] = session.get('place')['order_by']
        data['order_up'] = session.get('place')['order_up']
        data['find_key'] = session.get('place')['find_key']
        data['create_path'] = session.get('place')['create_path']
    if data['file_types'] in ('all', 'images'):
        data['custom_caption'] = 'Доступ'
        for get_file in os.listdir(f"static/users/{data['user']['id']}/files"):
            try:
                int(get_file.split("_v")[-1])
                if len(get_file.split("_v")) == 1:
                    raise ValueError
            except ValueError:
                if data['file_types'] == 'images' and \
                        (not os.path.isfile(f"static/users/{data['user']['id']}/files/{get_file}") or
                         os.path.splitext(get_file)[-1] not in image_types):
                    continue
                my_file = requests.get(f"{main_rest_ip}/file_info",
                                       json={"rest_key": rest_key, "user_id": data['user']['id'],
                                             "get_file": f"files/{get_file}"},
                                       headers={'Content-type': 'application/json'}).json()
                data['files'].append(my_file)
            else:
                continue
    elif data['file_types'] in ('checks', 'private'):
        data['custom_caption'] = 'Владелец'
        if data['file_types'] == 'checks':
            with open(f"static/users/{data['user']['id']}/check_files.json", 'r+') as cf:
                json_data = json.load(cf)
                cf.seek(0)
                for get_file in json_data:
                    get_access = requests.get(f"{main_rest_ip}/file_access",
                                              json={"rest_key": rest_key, "user_id": data['user']['id'],
                                                    "create_path": get_file,
                                                    "owner_id": re.split('/|\\\\', get_file)[0]},
                                              headers={'Content-type': 'application/json'}).json()['access']
                    if get_access:
                        my_file = requests.get(f"{main_rest_ip}/file_info",
                                               json={"rest_key": rest_key, "user_id": re.split('/|\\\\', get_file)[0],
                                                     "get_file": '/'.join(re.split('/|\\\\', get_file)[1:])},
                                               headers={'Content-type': 'application/json'}).json()
                        data['files'].append(my_file)
                    else:
                        json_data.remove(get_file)
                        json.dump(json_data, cf)
                        cf.truncate()
        else:
            for users_id in os.listdir("static/users"):
                if os.path.isdir(f"static/users/{users_id}"):
                    with open(f"static/users/{users_id}/file_access.json", 'r') as fa:
                        private_objects = json.load(fa)["private_objects"]
                        for po in private_objects:
                            for get_user in po["users"]:
                                if int(get_user["id"]) == data['user']['id']:
                                    my_file = requests.get(f"{main_rest_ip}/file_info",
                                                           json={"rest_key": rest_key, "user_id": users_id,
                                                                 "get_file": '/'.join(
                                                                     re.split("/|\\\\", po["filename"])[1:])},
                                                           headers={'Content-type': 'application/json'}).json()
                                    data['files'].append(my_file)
    elif data['file_types'] == "trash":
        data['custom_caption'] = ''
        for get_file in os.listdir(f"static/users/{data['user']['id']}/trash"):
            my_file = requests.get(f"{main_rest_ip}/file_info",
                                   json={"rest_key": rest_key, "user_id": data['user']['id'],
                                         "get_file": f"trash/{get_file}"},
                                   headers={'Content-type': 'application/json'}).json()
            data['files'].append(my_file)
    elif data['file_types'] == "select":
        if not os.path.exists(f"static/users/{data['create_path']}"):
            session['place']['create_path'] = ""
            session['place']['file_types'] = "all"
            return redirect("/")
        if int(re.split('/|\\\\', data['create_path'])[0]) != int(data['user']['id']):
            data['custom_caption'] = 'Владелец'
        v_path = data['create_path']
        for get_file in os.listdir(f"static/users/{v_path}"):
            try:
                int(get_file.split("_v")[-1])
                if len(get_file.split("_v")) == 1:
                    raise ValueError
            except ValueError:
                get_folder = '/'.join(re.split('/|\\\\', data['create_path'])[1:])
                get_access = requests.get(f"{main_rest_ip}/file_access",
                                          json={"rest_key": rest_key, "user_id": data['user']['id'],
                                                "create_path": data['create_path'],
                                                "owner_id": re.split('/|\\\\', data['create_path'])[0]},
                                          headers={'Content-type': 'application/json'}).json()['access']
                if get_access:
                    my_file = requests.get(f"{main_rest_ip}/file_info",
                                           json={"rest_key": rest_key,
                                                 "user_id": re.split('/|\\\\', data['create_path'])[0],
                                                 "get_file": f"{get_folder}/{get_file}"},
                                           headers={'Content-type': 'application/json'}).json()
                    data['files'].append(my_file)
    if data['order_by'] == "name":
        data['files'] = sorted(data['files'], key=lambda fk: fk['name'], reverse=data['order_up'])
    elif data['order_by'] == "date":
        data['files'] = sorted(data['files'], key=lambda fk: fk['full_update_time'], reverse=data['order_up'])
    elif data['order_by'] == "size":
        data['files'] = sorted(data['files'], key=lambda fk: fk['full_size'], reverse=data['order_up'])
    for file_key in data['files']:
        if data['find_key'] != "" and data['find_key'] in file_key['name']:
            data['files'].remove(file_key)
            file_key['finded'] = True
            data['files'].insert(0, file_key)
    if request.method == 'POST':
        if "_method_load" in session.keys() and session.get("_method_load") is not None:
            data = session.get("_method_load")
        if request.form['_method'] == "file_types":
            if not request.form['input_value'] in ('all', 'images'):
                data["create_path"] = ""
            session['place'] = {'linear': data['linear'], 'order_by': data['order_by'],
                                'order_up': data['order_up'], 'file_types': request.form['input_value'],
                                'find_key': "", 'create_path': data['create_path']}
            session.pop("_method_load", None)
            return redirect("/")
        if data['_method'] == "":
            is_downlink = False
            if request.form['_method'] in ["upload_file", "upload_directory"]:
                if request.form['_method'] == "upload_file":
                    flist = 'upload_files'
                else:
                    flist = 'upload_dirs'
                for i in request.files.getlist(flist):
                    if flist == 'upload_files' and "_" in os.path.splitext(i.filename)[-1] and \
                            "v" in os.path.splitext(i.filename)[-1]:
                        data['error'] = True
                        data['error_message'] = "Неподдерживаемый формат!"
                        shutil.rmtree(f"static/users/{data['user']['id']}/tmp")
                        return render_template("main.html", data=data)
                    if not os.path.isdir(f"static/users/{data['user']['id']}/tmp/{os.path.dirname(i.filename)}"):
                        os.makedirs(f"static/users/{data['user']['id']}/tmp/{os.path.dirname(i.filename)}")
                    i.save(f"static/users/{data['user']['id']}/tmp/{i.filename}")
                    data['progress']['used_bytes'] += os.path.getsize(
                        f"static/users/{data['user']['id']}/tmp/{i.filename}")
                if data['progress']['used_bytes'] > data['progress']['max_bytes']:
                    data['error'] = True
                    data['error_message'] = "Недостаточно места на диске!"
                else:
                    if data['create_path'] != "":
                        read_only = requests.get(f"{main_rest_ip}/file_access",
                                                 json={"rest_key": rest_key, "user_id": data['user']['id'],
                                                       "create_path": data['create_path'],
                                                       "owner_id": re.split('/|\\\\', data['create_path'])[0]},
                                                 headers={'Content-type': 'application/json'}).json()['readOnly']
                    else:
                        read_only = False
                    if data['file_types'] == "select" and read_only and \
                            int(data['user']['id']) != re.split('/|\\\\', data['create_path'])[0]:
                        data['error'] = True
                        data['error_message'] = "Нет доступа к редактированию данной папки!"
                        shutil.rmtree(f"static/users/{data['user']['id']}/tmp")
                        return render_template("main.html", data=data)
                    else:
                        for get_file in os.listdir(f"static/users/{data['user']['id']}/tmp"):
                            gf = get_file.split("_v")[-1]
                            try:
                                int(gf)
                                if len(get_file.split("_v")) == 1:
                                    raise ValueError
                            except ValueError:
                                if os.path.isdir(f"static/users/{data['user']['id']}/tmp/{get_file}"):
                                    for root, dirs, files in os.walk(
                                            f"static/users/{data['user']['id']}/tmp/{get_file}"):
                                        dirs_files = dirs + files
                                        for gd in dirs_files:
                                            try:
                                                int(gd.split("_v")[-1])
                                                if len(gd.split("_v")) == 1:
                                                    raise ValueError
                                            except ValueError:
                                                pass
                                            else:
                                                data['error'] = True
                                                data['error_message'] = "В папке содержатся неподдерживаемые обьекты!"
                                                shutil.rmtree(f"static/users/{data['user']['id']}/tmp")
                                                return render_template("main.html", data=data)
                                if data['file_types'] == "select":
                                    get_path = data['create_path']
                                else:
                                    get_path = f"{data['user']['id']}/files"
                                if not os.path.exists(os.path.join(f"static/users/{get_path}", get_file)):
                                    list_files = []
                                    if os.path.isdir(f"static/users/{data['user']['id']}/tmp/{get_file}"):
                                        for root, dirs, files in os.walk(
                                                f"static/users/{data['user']['id']}/tmp/{get_file}"):
                                            root = ''.join(re.split('/|\\\\', root)[4:])
                                            for name in dirs:
                                                list_files.append(f"{get_path}/{root}/{name}")
                                            for name in files:
                                                list_files.append(f"{get_path}/{root}/{name}")
                                    list_files.append(f"{get_path}/{get_file}")
                                    os.renames(f"static/users/{data['user']['id']}/tmp/{get_file}",
                                               f"static/users/{get_path}/{get_file}")
                                    with open("static/users/check_and_download.json", 'r+') as cad:
                                        json_data = json.load(cad)
                                        cad.seek(0)
                                        used_links = []
                                        for key in json_data:
                                            used_links.append(json_data[key]['private_link'])
                                            used_links.append(json_data[key]['public_link'])

                                        for i in list_files:
                                            new_links = []
                                            while len(new_links) < 2:
                                                link = ""
                                                while link == "" or link in used_links:
                                                    for ri in range(randint(32, 64)):
                                                        link += choice(list('1234567890abcdefghigklmnopqrstuvyxwz'
                                                                            'ABCDEFGHIGKLMNOPQRSTUVYXWZ'))
                                                new_links.append(link)

                                            json_data[i] = {'private_link': new_links[0], 'public_link': new_links[1]}
                                        json.dump(json_data, cad)
                                        cad.truncate()
                                    with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                                        json_data = json.load(fa)
                                        fa.seek(0)
                                        for i in list_files:
                                            if get_path == f"{data['user']['id']}/files":
                                                json_data['private_objects'].append({'filename': i, 'users': []})
                                            else:
                                                for key in json_data['private_objects']:
                                                    if key["filename"] == get_path:
                                                        json_data['private_objects'].append(
                                                            {'filename': i, 'users': key['users']})
                                                for key in json_data['open_objects']:
                                                    if key["filename"] == get_path:
                                                        json_data['open_objects'].append(
                                                            {'filename': i, 'readOnly': key['readOnly']})
                                        json.dump(json_data, fa)
                                        fa.truncate()
                                else:
                                    vers = 2
                                    while os.path.exists(f"static/users/{get_path}/{get_file}_v{vers}"):
                                        vers += 1
                                    os.rename(f"static/users/{data['user']['id']}/tmp/{get_file}",
                                              f"static/users/{get_path}/{get_file}_v{vers}")
                            else:
                                data['error'] = True
                                data['error_message'] = "Неверное имя обьекта!"
                                shutil.rmtree(f"static/users/{data['user']['id']}/tmp")
                                return render_template("main.html", data=data)
                if not data['error']:
                    return redirect("/")
            elif request.form['_method'] in ["create_file", "create_directory"]:
                data['_method'] = request.form['_method']
                session['_method_load'] = data
            elif request.form['_method'] == "access_settings":
                if int(re.split('/|\\\\', request.form['input_value'])[0]) == data['user']['id']:
                    data['selected_file'] = requests.get(f"{main_rest_ip}/file_info",
                                                         json={"rest_key": rest_key,
                                                               "user_id": re.split('/|\\\\',
                                                                                   request.form['input_value'])[0],
                                                               "get_file": '/'.join(
                                                                   re.split('/|\\\\',
                                                                            request.form['input_value'])[1:])},
                                                         headers={'Content-type': 'application/json'}).json()
                    data['access_param'] = requests.get(f"{main_rest_ip}/access_params",
                                                        json={"rest_key": rest_key, "file": request.form['input_value'],
                                                              "id": data['user']['id']},
                                                        headers={'Content-type': 'application/json'}).json()
                    with open("static/users/check_and_download.json", 'r') as cad:
                        json_data = json.load(cad)
                        for key in json_data.keys():
                            if key == request.form['input_value']:
                                data['down_urls'] = json_data[key]
                    data['_method'] = request.form['_method']
                    session['_method_load'] = data
            elif request.form['_method'] == "linear":
                session['place'] = {'linear': True, 'order_by': data['order_by'], "create_path": data["create_path"],
                                    'order_up': data['order_up'], 'file_types': data['file_types'], 'find_key': ""}
                return redirect("/")
            elif request.form['_method'] == "blocks":
                session['place'] = {'linear': False, 'order_by': data['order_by'], 'create_path': data['create_path'],
                                    'order_up': data['order_up'], 'file_types': data['file_types'], 'find_key': ""}
                return redirect("/")
            elif request.form['_method'] == "order_up":
                session['place'] = {'linear': data['linear'], 'order_by': data['order_by'],
                                    "create_path": data["create_path"], 'find_key': data['find_key'],
                                    'order_up': not data['order_up'], 'file_types': data['file_types']}
                return redirect("/")
            elif request.form['_method'] == "order_by":
                session['place'] = {'linear': data['linear'], 'order_by': request.form['input_value'],
                                    'order_up': data['order_up'], 'file_types': data['file_types'],
                                    'find_key': data['find_key'], 'create_path': data['create_path']}
                return redirect("/")
            elif request.form['_method'] == "find":
                session['place'] = {'linear': data['linear'], 'order_by': data['order_by'],
                                    'order_up': data['order_up'], 'file_types': data['file_types'],
                                    'find_key': request.form['finder'], 'create_path': data['create_path']}
                return redirect("/")
            elif request.form['_method'] == "open_file":
                if os.path.isdir(f"static/users/{request.form['input_value']}"):
                    session['place'] = {'linear': data['linear'], 'order_by': data['order_by'],
                                        'order_up': data['order_up'], 'file_types': 'select',
                                        'find_key': data['find_key'], 'create_path': request.form['input_value']}
                    return redirect("/")
                else:
                    is_downlink = True
            elif request.form['_method'] == "parent_dir":
                main_path = Path(data['create_path'])
                get_access = requests.get(f"{main_rest_ip}/file_access",
                                          json={"rest_key": rest_key, "user_id": data['user']['id'],
                                                "create_path": str(main_path.parent).replace("\\", "/"),
                                                "owner_id": re.split('/|\\\\', data['create_path'])[0]},
                                          headers={'Content-type': 'application/json'}).json()['access']
                if str(main_path.parent).replace("\\", "/") == f"{data['user']['id']}/files" or \
                        (int(data['user']['id']) != int(re.split("/|\\\\", data['create_path'])[0]) and not get_access):
                    session['place']['file_types'] = "all"
                    session['place']['create_path'] = ""
                elif str(main_path.parent).replace("\\", "/") == f"{data['user']['id']}/trash":
                    session['place']['file_types'] = "trash"
                    session['place']['create_path'] = ""
                else:
                    session['place']['create_path'] = str(main_path.parent)
                return redirect("/")
            elif request.form['_method'] == "download":
                is_downlink = True
            elif request.form['_method'] in ["autonomous", "not_autonomous"]:
                if not int(data['user']['id']) == int(re.split('/|\\\\', request.form['input_value'])[0]):
                    data['error'] = True
                    data['error_message'] = "Только владелец может настраивать доступ!"
                    return render_template("main.html", data=data)
                with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                    json_data = json.load(fa)
                    fa.seek(0)
                    if request.form['_method'] == "autonomous":
                        if not request.form['input_value'] in json_data["access_autonomous"]:
                            json_data["access_autonomous"].append(request.form['input_value'])
                    else:
                        if request.form['input_value'] in json_data["access_autonomous"]:
                            json_data["access_autonomous"].remove(request.form['input_value'])
                    json.dump(json_data, fa)
                    fa.truncate()
                    return redirect("/")
            elif request.form['_method'] == "checking_file":
                with open(f"static/users/{data['user']['id']}/check_files.json", 'r+') as cf:
                    json_data = json.load(cf)
                    if not request.form['input_value'] in json_data:
                        json_data.append(request.form['input_value'])
                    cf.seek(0)
                    json.dump(json_data, cf)
                    cf.truncate()
            if is_downlink:
                get_file = request.form['input_value']
                with open(f"static/users/check_and_download.json", 'r') as cad:
                    json_data = json.load(cad)
                    get_links = json_data[get_file]
                get_access = requests.get(f"{main_rest_ip}/file_access",
                                          json={"rest_key": rest_key, "user_id": data['user']['id'],
                                                "create_path": re.split('/|\\\\', get_file)[1:],
                                                "owner_id": re.split('/|\\\\', get_file)[0]},
                                          headers={'Content-type': 'application/json'}).json()
                if get_access['he_private']:
                    return redirect(f"/file/{get_links['private_link']}")
                else:
                    return redirect(f"/file/{get_links['public_link']}")
        else:
            set_users = False
            parrent_file = {}
            if data['_method'] in ("create_file", "create_directory"):
                obj_name = request.form["obj_name"]
                if data['_method'] == "create_file":
                    obj_type = "файла"
                else:
                    obj_type = "папки"
                data['error'] = True
                data['error_message'] = ''
                ban_symbols = ('*', '/', '\\', '|', '?', ':', "\"", '<', '>')
                ban_dirs = ('con', 'prn', 'aux', 'nul')
                if data['file_types'] == 'select':
                    get_path = data['create_path']
                else:
                    get_path = f"{data['user']['id']}/files"
                if obj_name == len(obj_name) * '.':
                    data['error_message'] = f"Неверное имя {obj_type}"
                else:
                    if obj_name in ban_dirs:
                        data['error_message'] = f"Неверное имя {obj_type}"
                    elif os.path.exists(f"static/users/{get_path}/{obj_name}"):
                        data['error_message'] = "Обьект уже сущесвует"
                    else:
                        for bs in ban_symbols:
                            if bs in obj_name:
                                data['error_message'] = f"Неверное имя {obj_type}"
                        if data['error_message'] == "":
                            try:
                                int(obj_name.split("_v")[-1])
                            except Exception:
                                pass
                            else:
                                if "_v" in obj_name:
                                    data['error_message'] = f"Неверное имя {obj_type}"
                            finally:
                                if "_v" not in obj_name:
                                    if data['create_path'] != "":
                                        read_only = requests.get(f"{main_rest_ip}/file_access",
                                                                 json={"rest_key": rest_key,
                                                                       "user_id": data['user']['id'],
                                                                       "create_path": data['create_path'],
                                                                       "owner_id":
                                                                           re.split('/|\\\\', data['create_path'])[0]},
                                                                 headers={'Content-type': 'application/json'}
                                                                 ).json()['readOnly']
                                    else:
                                        read_only = False
                                    if data['file_types'] == 'select' and read_only and \
                                            int(data['user']['id']) != int(re.split('/|\\\\', data['create_path'])[0]):
                                        data['error_message'] = f"Нет доступа к редактированию папки!"
                                    else:
                                        data['error'] = False
                                        if data['_method'] == "create_file":
                                            open(f"static/users/{get_path}/{obj_name}", 'x')
                                        else:
                                            os.mkdir(f"static/users/{get_path}/{obj_name}")
                                        with open("static/users/check_and_download.json", 'r+') as cad:
                                            json_data = json.load(cad)
                                            used_links = []
                                            for key in json_data:
                                                used_links.append(json_data[key]['private_link'])
                                                used_links.append(json_data[key]['public_link'])
                                            new_links = []
                                            while len(new_links) < 2:
                                                link = ""
                                                while link == "" or link in used_links:
                                                    for i in range(randint(32, 64)):
                                                        link += choice(list('1234567890abcdefghigklmnopqrstuvyxwz'
                                                                            'ABCDEFGHIGKLMNOPQRSTUVYXWZ'))
                                                new_links.append(link)
                                            cad.seek(0)
                                            json_data[f"{get_path}/{obj_name}"] = {
                                                'private_link': new_links[0], 'public_link': new_links[1]
                                            }
                                            json.dump(json_data, cad)
                                            cad.truncate()
                                        with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                                            json_data = json.load(fa)
                                            fa.seek(0)
                                            if get_path == f"{data['user']['id']}/files":
                                                json_data['private_objects'].append(
                                                    {'filename': f"{get_path}/{obj_name}", 'users': []})
                                            else:
                                                for key in json_data['private_objects']:
                                                    if key["filename"] == get_path:
                                                        json_data['private_objects'].append(
                                                            {'filename': f"{get_path}/{obj_name}",
                                                             'users': key['users']})
                                                for key in json_data['open_objects']:
                                                    if key["filename"] == get_path:
                                                        json_data['open_objects'].append(
                                                            {'filename': f"{get_path}/{obj_name}",
                                                             'readOnly': key['readOnly']})
                                            json.dump(json_data, fa)
                                            fa.truncate()
                                        session.pop("_method_load", None)
                                        return redirect("/")
                return render_template("main.html", data=data)
            elif data['_method'] == "access_settings":
                if request.form['_method'] == "save":
                    return redirect("/")
                elif request.form['_method'] == "open_access":
                    with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                        json_data = json.load(fa)
                        fa.seek(0)
                        new_open = {"filename": data["selected_file"]["path_name"], "readOnly": True}
                        if new_open not in json_data["open_objects"]:
                            json_data["open_objects"].append(new_open)
                        if os.path.isdir(f"static/users/{data['selected_file']['path_name']}"):
                            for root, dirs, files in os.walk(f"static/users/{data['selected_file']['path_name']}"):
                                dirs_files = dirs + files
                                for gf in dirs_files:
                                    try:
                                        int(gf.split("_v")[-1])
                                        if len(gf.split("_v")) == 1:
                                            raise ValueError
                                    except ValueError:
                                        if not '/'.join(re.split('/|\\\\', f"{root}/{gf}")[2:]) in \
                                               json_data["access_autonomous"]:
                                            new_open = {"filename": '/'.join(re.split('/|\\\\', f"{root}/{gf}")[2:]),
                                                        "readOnly": True}
                                            if new_open not in json_data["open_objects"]:
                                                json_data["open_objects"].append(new_open)
                        json.dump(json_data, fa)
                        fa.truncate()
                elif request.form['_method'] == "private_access":
                    with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                        json_data = json.load(fa)
                        fa.seek(0)
                        for gf in json_data["open_objects"]:
                            if gf["filename"] == data["selected_file"]["path_name"]:
                                json_data["open_objects"].remove(gf)
                            if os.path.isdir(f"static/users/{data['selected_file']['path_name']}"):
                                for root, dirs, files in os.walk(f"static/users/{data['selected_file']['path_name']}"):
                                    dirs_files = dirs + files
                                    for g_f in dirs_files:
                                        try:
                                            int(g_f.split("_v")[-1])
                                            if len(g_f.split("_v")) == 1:
                                                raise ValueError
                                        except ValueError:
                                            if not '/'.join(re.split('/|\\\\', f"{root}/{g_f}")[2:]) in \
                                                   json_data["access_autonomous"]:
                                                for gsf in json_data["open_objects"]:
                                                    if gsf["filename"] == '/'.join(
                                                            re.split('/|\\\\', f"{root}/{g_f}")[2:]):
                                                        json_data["open_objects"].remove(gsf)
                        json.dump(json_data, fa)
                        fa.truncate()
                elif request.form['_method'] in ("read_only", "not_read_only"):
                    with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                        json_data = json.load(fa)
                        fa.seek(0)
                        if request.form['_for'] == "public":
                            for gf in json_data["open_objects"]:
                                if gf["filename"] == data["selected_file"]["path_name"]:
                                    if request.form['_method'] == "read_only":
                                        json_data["open_objects"][json_data["open_objects"].index(gf)][
                                            "readOnly"] = True
                                    else:
                                        json_data["open_objects"][json_data["open_objects"].index(gf)][
                                            "readOnly"] = False
                                    if os.path.isdir(f"static/users/{data['selected_file']['path_name']}"):
                                        for root, dirs, files in os.walk(
                                                f"static/users/{data['selected_file']['path_name']}"):
                                            dirs_files = dirs + files
                                            for g_f in dirs_files:
                                                try:
                                                    int(g_f.split("_v")[-1])
                                                    if len(g_f.split("_v")) == 1:
                                                        raise ValueError
                                                except ValueError:
                                                    if not '/'.join(re.split('/|\\\\', f"{root}/{g_f}")[2:]) in \
                                                           json_data["access_autonomous"]:
                                                        for gsf in json_data["open_objects"]:
                                                            if gsf["filename"] == '/'.join(
                                                                    re.split('/|\\\\', f"{root}/{g_f}")[2:]):
                                                                json_data["open_objects"][
                                                                    json_data["open_objects"].index(gsf)][
                                                                    "readOnly"] = json_data["open_objects"][
                                                                    json_data["open_objects"].index(gf)]["readOnly"]
                        elif request.form['_for'].split("_")[0] == "id":
                            for gf in json_data["private_objects"]:
                                if gf["filename"] == data["selected_file"]["path_name"]:
                                    for g_user in gf['users']:
                                        if int(g_user['id']) == int(request.form['_for'].split("_")[1]):
                                            if request.form['_method'] == "read_only":
                                                json_data["private_objects"][json_data["private_objects"].index(gf)][
                                                    "users"][gf['users'].index(g_user)]["readOnly"] = True
                                            else:
                                                json_data["private_objects"][json_data["private_objects"].index(gf)][
                                                    "users"][gf['users'].index(g_user)]["readOnly"] = False
                                            set_users = True
                                            parrent_file = gf
                        json.dump(json_data, fa)
                        fa.truncate()
                elif request.form['_method'] == "delete_access":
                    with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                        json_data = json.load(fa)
                        fa.seek(0)
                        for gf in json_data["private_objects"]:
                            if gf["filename"] == data["selected_file"]["path_name"]:
                                for g_user in gf['users']:
                                    if int(g_user['id']) == int(request.form['_for'].split("_")[1]):
                                        json_data["private_objects"][json_data["private_objects"].index(gf)][
                                            "users"].remove(g_user)
                                        set_users = True
                                        parrent_file = gf

                        json.dump(json_data, fa)
                        fa.truncate()
                elif request.form['_method'] == "finded_access":
                    all_users = requests.get(f"{main_rest_ip}user", json={"rest_key": rest_key},
                                             headers={'Content-type': 'application/json'}).json()
                    data['access_fined_key'] = request.form['access_add']
                    for i in all_users['users']:
                        if not i['id'] == data['user']['id'] and request.form['access_add'] in i['username']:
                            data['access_fined_users'].append(i)
                    data['access_fined'] = True
                elif request.form['_method'] == "add_access":
                    with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                        json_data = json.load(fa)
                        fa.seek(0)
                        for gf in json_data["private_objects"]:
                            if gf["filename"] == data["selected_file"]["path_name"]:
                                new_user = {
                                    "id": int(request.form['_for'].split("_")[1]), "readOnly": True
                                }
                                if new_user not in json_data["private_objects"][json_data["private_objects"].index(gf)]['users']:
                                    json_data["private_objects"][json_data["private_objects"].index(gf)]['users'].append({
                                        "id": int(request.form['_for'].split("_")[1]), "readOnly": True
                                    })
                                data['access_fined'] = False
                                set_users = True
                                parrent_file = gf
                        json.dump(json_data, fa)
                        fa.truncate()
                if set_users:
                    with open(f"static/users/{data['user']['id']}/file_access.json", 'r+') as fa:
                        json_data = json.load(fa)
                        fa.seek(0)
                        if os.path.isdir(f"static/users/{data['selected_file']['path_name']}"):
                            for root, dirs, files in os.walk(
                                    f"static/users/{data['selected_file']['path_name']}"):
                                dirs_files = dirs + files
                                for g_f in dirs_files:
                                    try:
                                        int(g_f.split("_v")[-1])
                                        if len(g_f.split("_v")) == 1:
                                            raise ValueError
                                    except ValueError:
                                        if not '/'.join(re.split('/|\\\\', f"{root}/{g_f}")[2:]) in \
                                               json_data["access_autonomous"]:
                                            for gsf in json_data["private_objects"]:
                                                if gsf["filename"] == '/'.join(
                                                        re.split('/|\\\\', f"{root}/{g_f}")[2:]):
                                                    json_data["private_objects"][
                                                        json_data["private_objects"].index(gsf)][
                                                        "users"] = json_data["private_objects"][
                                                        json_data["private_objects"].index(parrent_file)][
                                                        "users"]
                        json.dump(json_data, fa)
                        fa.truncate()
                data['selected_file'] = requests.get(f"{main_rest_ip}/file_info",
                                                     json={"rest_key": rest_key,
                                                           "user_id": re.split('/|\\\\',
                                                                               data["selected_file"]["path_name"])[0],
                                                           "get_file": '/'.join(
                                                               re.split('/|\\\\',
                                                                        data["selected_file"]["path_name"])[1:])},
                                                     headers={'Content-type': 'application/json'}).json()
                data['access_param'] = requests.get(f"{main_rest_ip}/access_params",
                                                    json={"rest_key": rest_key,
                                                          "file": data["selected_file"]["path_name"],
                                                          "id": data['user']['id']},
                                                    headers={'Content-type': 'application/json'}).json()
                session['_method_load'] = data
    else:
        if data['file_types'] != "versions":
            session.pop("_method_load", None)
    return render_template("main.html", data=data)


@app.route('/edit', methods=['GET', 'POST'])
def edit():
    if "user_id" not in session.keys() or session.get("user_id") is None or session.get("user_id") <= 0:
        return redirect("/")
    if not ("2fa_user" not in session.keys() or session.get("2fa_user") is None):
        session.pop("2fa_user", None)
    if os.path.isfile(f"static/qr_auth{session.get('user_id')}.png"):
        os.remove(f"static/qr_auth{session.get('user_id')}.png")
    recaptha = ReCaptha()
    data = {
        "title": "Ваш аккаунт",
        "default_icon": url_for('.static', filename="img/user.svg"),
        "user": requests.get(f"{main_rest_ip}user/{session.get('user_id')}", json={"rest_key": rest_key},
                             headers={'Content-type': 'application/json'}).json(),
        "error": False,
        "error_message": "",
        "old_password": "",
        "new_password": "",
        "new_valid_password": "",
        "time_icon": "",
        "code": -1,
        "code_iteration": 0,
        "date": {"date": "", "time": ""}
    }
    date = datetime.datetime.strptime(data['user']['register_time'], '%a, %d %b %Y %H:%M:%S GMT')
    data['date'] = {"date": date.strftime('%d.%m.%Y'), "time": date.strftime('%H:%M')}
    if "save_user" in session.keys() and not session['save_user'] is None:
        data = session['save_user']
    if request.method == 'POST':
        if ('_method' in request.form and request.form['_method'] == 'put') or data['code'] >= 0:
            if data['code'] < 0:
                data['error'] = True
                if not recaptha.validate_on_submit():
                    data['error_message'] = "Подтвердите, что вы не робот!"
                elif data['user']['password_hash'] != hashlib.sha256(
                        request.form['old_password'].encode('utf-8')).hexdigest():
                    data['error_message'] = "Неверный пароль!"
                elif request.form['new_password'] != request.form['new_valid_password']:
                    data['error_message'] = "Подтвердите пароль!"
                else:
                    data['error'] = False
                if data['error']:
                    return render_template("edit_user.html", data=data, recaptha=recaptha)

            if ('email' in request.form and request.form['email'] != data['user']['email']) or data['code'] >= 0:
                data['error'] = False
                if data['code'] >= 0:
                    if str(data['code']) == request.form['code']:
                        session.pop('save_user', None)
                        if data['user']['_2fa']:
                            session['2fa_user'] = {"user": data['user'],
                                                   "new_password": None, "data": None, "_method": "update"}
                            return redirect("/2fa_code")
                        else:
                            if os.path.isfile(f"static/users/{data['user']['id']}/icon_.png"):
                                os.rename(f"static/users/{data['user']['id']}/icon_.png", "icon.png")
                            p_json = {"rest_key": rest_key, "username": data['user']['username'],
                                      "email": data['user']['email'], "phone_number": data['user']['phone_number']}
                            if data['new_password'] != '':
                                p_json["password_hash"] = hashlib.sha256(
                                    data['new_password'].encode('utf-8')).hexdigest()
                            requests.put(f"{main_rest_ip}user/{session.get('user_id')}", json=p_json,
                                         headers={'Content-type': 'application/json'})
                            return redirect("/")
                    else:
                        data['error'] = True
                        if data["code_iteration"] >= 3:
                            data[
                                'error_message'] = "Слишком много попыток!\nВам на почту пришёл новый код подтверждения!"
                            data['code'] = randint(0, 999999)

                            requests.post(f"{main_rest_ip}email",
                                          json={"rest_key": rest_key, "email": data['user']['email'],
                                                "code": data['code']},
                                          headers={'Content-type': 'application/json'})

                            data["code_iteration"] = 0
                        else:
                            data['error_message'] = "Неверный проверочный код!"
                            data["code_iteration"] += 1
                else:
                    data['code'] = randint(0, 999999)
                    requests.post(f"{main_rest_ip}email", json={"rest_key": rest_key, "email": request.form['email'],
                                                                "code": data['code']},
                                  headers={'Content-type': 'application/json'})
                    data["code_iteration"] = 0
                    data['user']['username'] = request.form['login']
                    data['user']['email'] = request.form['email']
                    data['old_password'] = request.form['old_password']
                    data['new_password'] = request.form['new_password']
                    data['new_valid_password'] = request.form['new_valid_password']
                    data['user']['phone_number'] = request.form['phone_number']
                session['save_user'] = data
            else:
                session.pop('save_user', None)
                if data['user']['_2fa']:
                    if request.form['new_password'] != '':
                        data['user']['password_hash'] = hashlib.sha256(
                            request.form['new_password'].encode('utf-8')).hexdigest()
                    data['user']['username'] = request.form['login']
                    data['user']['phone_number'] = request.form['phone_number']
                    session['2fa_user'] = {"user": data['user'],
                                           "new_password": None, "data": None, "_method": "update"}
                    return redirect("/2fa_code")
                else:
                    if os.path.isfile(f"static/users/{data['user']['id']}/icon_.png"):
                        if os.path.isfile(f"static/users/{data['user']['id']}/icon.png"):
                            os.remove(f"static/users/{data['user']['id']}/icon.png")
                        os.rename(f"static/users/{data['user']['id']}/icon_.png",
                                  f"static/users/{data['user']['id']}/icon.png")
                    data['user']['username'] = request.form['login']
                    data['user']['email'] = request.form['email']
                    data['old_password'] = request.form['old_password']
                    data['new_password'] = request.form['new_password']
                    data['new_valid_password'] = request.form['new_valid_password']
                    data['user']['phone_number'] = request.form['phone_number']
                    p_json = {"rest_key": rest_key, "username": data['user']['username'],
                              "email": data['user']['email'], "phone_number": data['user']['phone_number']}
                    if data['new_password'] != '':
                        p_json["password_hash"] = hashlib.sha256(data['new_password'].encode('utf-8')).hexdigest()
                    requests.put(f"{main_rest_ip}user/{session.get('user_id')}", json=p_json,
                                 headers={'Content-type': 'application/json'}).json()

                    return redirect("/")
            return render_template("edit_user.html", data=data, recaptha=recaptha)
        elif request.form['_method'] == 'delete':
            data['error'] = True
            if not recaptha.validate_on_submit():
                data['error_message'] = "Подтвердите, что вы не робот!"
            elif data['user']['password_hash'] != hashlib.sha256(
                    request.form['old_password'].encode('utf-8')).hexdigest():
                data['error_message'] = "Неверный пароль!"
            else:
                data['error'] = False
                if data['user']['_2fa']:
                    session['2fa_user'] = {"user": requests.get(f"{main_rest_ip}user/{data['user']['id']}",
                                                                json={"rest_key": rest_key},
                                                                headers={'Content-type': 'application/json'}).json(),
                                           "new_password": None, "data": None, "_method": "delete"}
                    session.modified = True
                    session.permanent = True
                    return redirect("/2fa_code")
                else:
                    requests.delete(f"{main_rest_ip}user/{session.get('user_id')}", json={"rest_key": rest_key},
                                    headers={'Content-type': 'application/json'})

                    session.pop('user_id', None)
                    return redirect("/")
            return render_template("edit_user.html", data=data, recaptha=recaptha)
        elif request.form['_method'] == 'exit':
            session.pop('user_id', None)
            return redirect("/")
        elif request.form['_method'] == 'update_icon':
            data['user']['username'] = request.form['login']
            data['user']['email'] = request.form['email']
            data['old_password'] = request.form['old_password']
            data['new_password'] = request.form['new_password']
            data['new_valid_password'] = request.form['new_valid_password']
            data['user']['phone_number'] = request.form['phone_number']
            data['time_icon'] = "_"
            icon = request.files['icon_file']
            icon.filename = "icon_.png"
            if not os.path.isdir(f'static/users/{data["user"]["id"]}/'):
                os.makedirs(f'static/users/{data["user"]["id"]}/')
            icon.save(os.path.join(f'static/users/{data["user"]["id"]}/', icon.filename))
            return render_template("edit_user.html", data=data, recaptha=recaptha)
    else:
        return render_template("edit_user.html", data=data, recaptha=recaptha)


@app.route('/edit/2fa', methods=['GET', 'POST'])
def add_2fa():
    if "user_id" not in session.keys() or session.get("user_id") is None or session.get("user_id") <= 0:
        return redirect("/")
    if not ("2fa_user" not in session.keys() or session.get("2fa_user") is None):
        session.pop("2fa_user", None)
    data = {
        "title": "Двухфакторная аутентификация",
        "code": -1,
        "code_iteration": 0,
        "user": requests.get(f"{main_rest_ip}user/{session.get('user_id')}", json={"rest_key": rest_key},
                             headers={'Content-type': 'application/json'}).json(),
        "error": False,
        "error_message": "",
        "google_verify": False,
        "google_key": requests.post(f"{main_rest_ip}/google_auth/{session.get('user_id')}", json={"rest_key": rest_key},
                                    headers={'Content-type': 'application/json'}).json()['key'],
        "reserve_codes": []
    }
    if request.method == 'POST':
        if "add_2fa" in session.keys() and not session.get("add_2fa") is None:
            data = session.get('add_2fa')
        if data['code'] >= 0:
            if str(data['code']) == request.form['code']:
                requests.put(f"{main_rest_ip}user/{session.get('user_id')}", json={"rest_key": rest_key, "_2fa": True},
                             headers={'Content-type': 'application/json'})
                session.pop('add_2fa', None)
                return redirect("/edit/2fa")
            else:
                data['error'] = True
                if data["code_iteration"] >= 3:
                    data['error_message'] = "Слишком много попыток!\nВам на телефон пришёл новый код подтверждения!"
                    data['code'] = randint(0, 999999)

                    requests.post(f"{main_rest_ip}sms", json={"rest_key": rest_key,
                                                              "phone_number": data['user']['phone_number'],
                                                              "code": data['code']},
                                  headers={'Content-type': 'application/json'})

                    data["code_iteration"] = 0
                else:
                    data['error_message'] = "Неверный проверочный код!"
                    data["code_iteration"] += 1
                session['add_2fa'] = data
        elif data['google_verify']:
            google_rest = requests.get(f"{main_rest_ip}/google_auth/{session.get('user_id')}",
                                       json={"rest_key": rest_key, "google_key": data['google_key'],
                                             "code": request.form['code']},
                                       headers={'Content-type': 'application/json'})

            verify = google_rest.json()['verify']
            if verify:
                requests.put(f"{main_rest_ip}user/{session.get('user_id')}",
                             json={"rest_key": rest_key, "google_key": data['google_key']},
                             headers={'Content-type': 'application/json'})
                session.pop('add_2fa', None)
                session.modified = True
                session.permanent = True
                return redirect("/edit/2fa")
            else:
                data['error'] = True
                data['error_message'] = "Неверный код подтверждения!"
                session['add_2fa'] = data
        elif request.form['_method'] == 'add_2fa':
            if '_2fa' in request.form.keys() and request.form['_2fa'] == 'on':
                data['code'] = randint(0, 999999)
                requests.post(f"{main_rest_ip}sms", json={"rest_key": rest_key,
                                                          "phone_number": data['user']['phone_number'],
                                                          "code": data['code']},
                              headers={'Content-type': 'application/json'})
                data["code_iteration"] = 0
                session['add_2fa'] = data
            else:
                data['user']['_2fa'] = False
                session['2fa_user'] = {"user": data['user'], "new_password": None, "data": None, "_method": "update"}
                return redirect("/2fa_code")
        elif request.form['_method'] == 'reserve_code':
            if not data['user']['_2fa']:
                data['error'] = True
                data['error_message'] = "Сначала включите 2FA"
            else:
                while len(data['user']['reserve_code']) < 80:
                    data['user']['reserve_code'] += str(randint(10000000, 99999999))
                requests.put(f"{main_rest_ip}user/{session.get('user_id')}",
                             json={"rest_key": rest_key, "reserve_code": data['user']['reserve_code']},
                             headers={'Content-type': 'application/json'})
                data['reserve_codes'] = [data['user']['reserve_code'][i:i + 8] for i in range(0, 80, 8)]
        elif request.form['_method'] == 'google_auth':
            if not data['user']['_2fa']:
                data['error'] = True
                data['error_message'] = "Сначала включите 2FA"
            else:
                data['google_key'] = request.form['gkey']
                data['google_verify'] = True
                session['add_2fa'] = data
        elif request.form['_method'] == 'save':
            return redirect("/edit")
    else:
        session.pop("add_2fa", None)
    return render_template("add_2fa.html", data=data)


@app.route('/2fa_code', methods=['GET', 'POST'])
def _2fa_code():
    if "2fa_user" not in session.keys() or session.get("2fa_user") is None:
        return redirect("/")
    data = {
        "title": "Подтверждение номера телефона",
        "caption_text": "Введите ваш код 2FA для подтверждения номера телефона",
        "user": session['2fa_user']['user'],
        "new_password": session['2fa_user']['new_password'],
        "_method": session['2fa_user']['_method'],
        "code": -1,
        "code_iteration": 0,
        "error": False,
        "error_message": "",
        "code_input": False,
        "reserve_input": 0
    }
    if request.method == 'POST':
        data = session.get("2fa_user")
        is_verify = False
        if data['code_input']:
            if data['reserve_input'] > 0:
                reserve_codes = [data['user']['reserve_code'][i:i + 8] for i in
                                 range(0, len(data['user']['reserve_code']), 8)]
                if request.form['code'] in reserve_codes:
                    data['error'] = False
                    reserve_codes.remove(request.form['code'])
                    reserve_code = ""
                    for i in reserve_codes:
                        reserve_code += i
                    requests.put(f"{main_rest_ip}user/{data['user']['id']}", json={"rest_key": rest_key,
                                                                                   "reserve_code": reserve_code},
                                 headers={'Content-type': 'application/json'})
                    is_verify = True
                else:
                    data['error'] = True
                    data['error_message'] = "Резервный код не найден!"
            else:
                google_rests = requests.get(f"{main_rest_ip}/google_auth/{data['user']['id']}",
                                            json={"rest_key": rest_key, "google_key": data['user']['google_key'],
                                                  "code": request.form['code']},
                                            headers={'Content-type': 'application/json'})
                google_rest = google_rests.json()['verify']
                if google_rest:
                    data['error'] = False
                    is_verify = True
                else:
                    data['error'] = True
                    data['error_message'] = "Неверный код!"
        else:
            if request.form['_method'] == 'verify':
                data = session.get("2fa_user")
                if str(data['code']) == request.form['2fa_code']:
                    data['error'] = False
                    is_verify = True
                else:
                    data['error'] = True
                    if data["code_iteration"] >= 3:
                        data['error_message'] = "Слишком много попыток!\nВам на телефон пришёл новый код подтверждения!"
                        data['code'] = randint(0, 999999)

                        requests.post(f"{main_rest_ip}sms", json={"rest_key": rest_key,
                                                                  "phone_number": data['user']['phone_number'],
                                                                  "code": data['code']},
                                      headers={'Content-type': 'application/json'})

                        data["code_iteration"] = 0
                    else:
                        data['error_message'] = "Неверный проверочный код!"
                        data["code_iteration"] += 1
            elif request.form['_method'] == 'send_sms':
                data['code'] = randint(0, 999999)
                requests.post(f"{main_rest_ip}sms", json={"rest_key": rest_key,
                                                          "phone_number": data['user']['phone_number'],
                                                          "code": data['code']},
                              headers={'Content-type': 'application/json'})
                data["code_iteration"] = 0
            elif request.form['_method'] == 'reserve_code':
                data['reserve_input'] = 1
                data['code'] = -1
                data['code_iteration'] = 0
                data['reserve_input'] = True
                data['code_input'] = True
            elif request.form['_method'] == 'google_auth':
                data['code'] = -1
                data['code_iteration'] = 0
                data['code_input'] = True
        if is_verify:
            session.pop("2fa_user", None)
            session.modified = True
            session.permanent = True
            if data['_method'] == "auth":
                if not data['new_password'] is None:
                    requests.post(f"{main_rest_ip}email", json={"rest_key": rest_key, "email": data['user']['email'],
                                                                "new_password": data['new_password'], "code": -1},
                                  headers={'Content-type': 'application/json'})
                    requests.put(f"{main_rest_ip}user/{data['user']['id']}",
                                 json={"rest_key": rest_key,
                                       "password_hash": hashlib.sha256(data['new_password'].encode('utf-8')).hexdigest()
                                       }, headers={'Content-type': 'application/json'})
                session['user_id'] = data['user']['id']
                session.modified = True
                session.permanent = True
                return redirect("/")
            elif data['_method'] == "update":
                if os.path.isfile(f"static/users/{data['user']['id']}/icon_.png"):
                    if os.path.isfile(f"static/users/{data['user']['id']}/icon.png"):
                        os.remove(f"static/users/{data['user']['id']}/icon.png")
                    os.rename(f"static/users/{data['user']['id']}/icon_.png",
                              f"static/users/{data['user']['id']}/icon.png")
                requests.put(f"{main_rest_ip}user/{data['user']['id']}",
                             json={"rest_key": rest_key, "_2fa": data['user']['_2fa'],
                                   "username": data['user']['username'], "email": data['user']['email'],
                                   "phone_number": data['user']['phone_number'],
                                   "password_hash": data['user']['password_hash']},
                             headers={'Content-type': 'application/json'})
                return redirect("/")
            elif data['_method'] == "delete":
                requests.delete(f"{main_rest_ip}user/{data['user']['id']}", json={"rest_key": rest_key},
                                headers={'Content-type': 'application/json'})
                session.pop('user_id', None)
                return redirect("/")
        else:
            session['2fa_user'] = data
    else:
        session['2fa_user'] = data
    return render_template("verify_phone.html", data=data)


@app.route('/file/<string:file>', methods=['GET', 'POST'])
def check_file_path(file):
    file_path = ""
    is_private = False
    with open("static/users/check_and_download.json", 'r') as cad:
        json_data = json.load(cad)
        for key in json_data.keys():
            if json_data[key]["private_link"] == file:
                file_path = key
                is_private = True
            elif json_data[key]["public_link"] == file:
                file_path = key
                is_private = False
    if file_path == "":
        abort(404)
    data = {
        "title": "Скачать файл",
        "user_id": 0,
        "owner_id": re.split("/|\\\\", file_path)[0],
        "file": {}
    }
    # Формат которые поддерживают редактиварование
    edit_types = []
    if "user_id" in session.keys():
        data['user_id'] = session.get('user_id')
    get_access = requests.get(f"{main_rest_ip}/file_access",
                              json={"rest_key": rest_key, "user_id": data['user_id'],
                                    "create_path": file_path, "owner_id": data['owner_id']},
                              headers={'Content-type': 'application/json'}).json()
    if not get_access['access']:
        abort(403)
    elif get_access['private'] and not is_private:
        abort(404)
    if is_private and not get_access['he_private']:
        abort(403)
    edit = False
    if not get_access['readOnly'] and os.path.splitext(re.split('/|\\\\', file_path)[-1]) in edit_types:
        if is_private or not get_access['public_read']:
            edit = True
    vers = 2
    used_path = file_path
    while os.path.exists(f"static/users/{file_path}_v{vers}"):
        used_path = f"{file_path}_v{vers}"
        vers += 1
    data['file'] = requests.get(f"{main_rest_ip}/file_info",
                                json={"rest_key": rest_key, "user_id": re.split('/|\\\\', used_path)[0],
                                      "get_file": '/'.join(re.split('/|\\\\', used_path)[1:])},
                                headers={'Content-type': 'application/json'}).json()
    if not edit:
        session["download_file"] = {"filename": f"static/users/{used_path}", "user_id": data['user_id'],
                                    "owner_id": data['owner_id']}
        try:
            int(data['file']['name'].split("_v")[-1])
        except ValueError:
            pass
        else:
            if len(data['file']['name'].split("_v")) != 1:
                data['file']['name'] = ''.join(data['file']['name'].split("_v")[:-1])
        return render_template("download.html", data=data)


@app.route('/download_version/<string:file>', methods=['GET', 'POST'])
def download_version(file):
    gf = requests.get(f"{main_rest_ip}/file_info",
                      json={"rest_key": rest_key, "user_id": re.split('/|\\\\', file)[0],
                            "get_file": '/'.join(re.split('/|\\\\', file)[1:])},
                      headers={'Content-type': 'application/json'}).json()
    get_access = requests.get(f"{main_rest_ip}/file_access",
                              json={"rest_key": rest_key, "user_id": session.get('user_id'),
                                    "create_path": file, "owner_id": gf['owner_id']},
                              headers={'Content-type': 'application/json'}).json()
    if get_access['access']:
        session["download_file"] = {"filename": f"static/users/{file}", "user_id": session.get('user_id'),
                                    "owner_id": gf['owner_id']}
        return redirect("/download")
    else:
        abort(403)


@app.route('/download', methods=['GET', 'POST'])
def download():
    if "download_file" in session.keys():
        sess_date = session.get("download_file")
        path = sess_date['filename']
        down_name = os.path.basename(path)
        try:
            int(os.path.basename(path).split("_v")[-1])
        except ValueError:
            pass
        else:
            if not len(os.path.basename(path).split("_v")) == 1:
                down_name = ''.join(os.path.basename(path).split("_v")[:-1])
        if os.path.isdir(path):
            create_name = ""
            while create_name == '' or os.path.exists(create_name):
                create_name = ""
                for i in range(randint(8, 16)):
                    create_name += choice(list('1234567890abcdefghigklmnopqrstuvyxwz'
                                               'ABCDEFGHIGKLMNOPQRSTUVYXWZ'))
            shutil.make_archive(f"static/tmp/{create_name}", 'zip', path)
            with open("static/users/removes.json", 'r+') as rems:
                json_data = json.load(rems)
                rems.seek(0)
                json_data.append(f"static/tmp/{create_name}.zip")
                json.dump(json_data, rems)
                rems.truncate()
            not_access_files = []
            for root, dirs, files in os.walk(path):
                for gf in files:
                    access_file = requests.get(f"{main_rest_ip}/file_access",
                                               json={"rest_key": rest_key, "user_id": sess_date['user_id'],
                                                     "create_path": gf, "owner_id": sess_date['owner_id']},
                                               headers={'Content-type': 'application/json'}).json()
                    if not access_file['access']:
                        not_access_files.append(gf)
                for gd in files:
                    access_file = requests.get(f"{main_rest_ip}/file_access",
                                               json={"rest_key": rest_key, "user_id": sess_date['user_id'],
                                                     "create_path": gd, "owner_id": sess_date['owner_id']},
                                               headers={'Content-type': 'application/json'}).json()
                    if not access_file['access']:
                        not_access_files.append(gd)
            for naf in not_access_files:
                delete_from_zip_file(f"static/tmp/{create_name}.zip", pattern=naf)
            down_name = f"{down_name}.zip"
            path = f"static/tmp/{create_name}.zip"
        return send_file(path, download_name=down_name, as_attachment=True)
    else:
        abort(404)


# Запуск сайта
if __name__ == '__main__':
    app.run(debug=True, port=5000)
