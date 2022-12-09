# подключение

from flask import Flask, request, redirect, jsonify, make_response
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
import sqlite3, uuid, hashlib, random
from werkzeug.security import generate_password_hash, check_password_hash

conn = sqlite3.connect('database.db', check_same_thread=False)
cursor = conn.cursor()

# создание таблицы с юзерами

cursor.execute('''CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER NOT NULL UNIQUE,
    "login" TEXT NOT NULL UNIQUE,
    "password" TEXT NOT NULL,
    PRIMARY KEY("id" AUTOINCREMENT)
    );''')
conn.commit()

# создание таблицы с ссылками

cursor.execute('''CREATE TABLE IF NOT EXISTS "links" (
    "id" INTEGER NOT NULL,
    "login" TEXT NOT NULL,
    "begin_link" TEXT NOT NULL,
    "short_link" TEXT NOT NULL,
    "access" TEXT NOT NULL,
    "count_of_redirection"	INTEGER NOT NULL,
    PRIMARY KEY("id" AUTOINCREMENT)
    );''')
conn.commit()

# --------------------------------------------------------------------------------------------------------------------------

# ОБЩЕЕ ИСПОЛЬЗОВАНИЕ

# функция на проверку юзера
def isUser (cursor, connect, login) :
    sql = "SELECT users.* FROM users WHERE login= :login"
    result = cursor.execute(sql, {'login': login}).fetchone()
    connect.commit()
    return result

# функция для вывода ссылок юзера
def allLinksOfUser (cursor, conn, login) :
    sql = "SELECT links.short_link FROM links WHERE login= :login"
    result = cursor.execute(sql, {'login': login}).fetchall()
    conn.commit()
    return result

# функция для добавления ссылки
def addLinks (cursor, conn, login, begin_link, short_link, access, count_of_redirection) :
    sql = "INSERT INTO links (login, begin_link, short_link, access, count_of_redirection) VALUES (:login, :begin_link, :short_link, :access, :count_of_redirection)"
    cursor.execute(sql, {'login':login, 'begin_link':begin_link, 'short_link':short_link, 'access':access, 'count_of_redirection':count_of_redirection})
    conn.commit()

# функция для удаления ссылки
def delLinks (cursor, conn, short_link, login) :
    sql = "DELETE FROM links WHERE login=:login AND short_link=:short_link"
    cursor.execute(sql, {'short_link': short_link, 'login': login})
    conn.commit()

#функция для изменения сокращенной ссылки
def changeShLinks (cursor, conn, old_short_link, new_short_link, login) :
    sql = "UPDATE links SET short_link=:new_short_link WHERE short_link=:old_short_link AND login=:login"
    cursor.execute(sql, {'old_short_link': old_short_link, 'new_short_link': new_short_link, 'login': login})
    conn.commit()

# функция для изменения доступа ссылки
def changeAccLinks (cursor, conn, short_link, access, login) :
    sql = "UPDATE links SET access=:access WHERE short_link=:short_link AND login=:login"
    cursor.execute(sql, {'short_link': short_link, 'access': access, 'login': login})
    conn.commit()

# функция для сокращенной ссылки
def getLink (cursor, conn, short_link) :
    result = cursor.execute("SELECT links.* FROM links WHERE short_link=:short_link", {'short_link': short_link}).fetchone()
    conn.commit()
    return result

# функция для подсчета переходов по ссылке
def getLinkAndKol (cursor, conn, short_link, count_of_redirection) :
    result = cursor.execute('''UPDATE links SET count_of_redirection=? WHERE short_link=?''', (count_of_redirection + 1, short_link,))
    conn.commit()
    return result

# ------------------------------------------------------------

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "dfghjkllkjh313"
jwt = JWTManager(app)

# ------------------------------------------------------------

# функция для регистрации
@app.route('/register', methods = ["post"])
def reg():
    if request.method == 'POST':
        login = str(request.json.get('login', None))
        password = str(request.json.get('password', None))

        #проверка на пустоту в строке
        if (login != '') & (password != ''):
            return make_response(regis_user(cursor, conn, login, password))
        else:
            return make_response("Введите данные!")
def regis_user(cursor, conn, login, password):
    proverka = cursor.execute('SELECT login FROM users').fetchall()
    users = []
    for item in proverka:
        users.append(item[0])
    if (login in users):
        return make_response("Такой пользователь уже есть")
    else:
        cursor.execute('INSERT INTO users(login, password) VALUES(?, ?)', (login, generate_password_hash(password)))
        conn.commit()
        return make_response("Вы успешно зарегистрировались")

# ------------------------------------------------------------

# функция для авторизации
@app.route('/autho', methods = ["post"])
def authorize():
    if request.method == 'POST':
        login = str(request.json.get('login', None))
        password = str(request.json.get('password', None))

        # проверка на пустоту в строке
        if (login != '') & (password != ''):
            user = isUser(cursor, conn, login)
            if user != None:
                return make_response(auth_user(cursor, conn, user, login, password))
            else:
                return ("Такого пользователя нет!")
        else:
            return make_response("Введите данные!")
def auth_user(cursor, conn, user, login, password):
    if check_password_hash(user[2], password):
        token = create_access_token(identity=login)
        return make_response(f" Пользователь с логином, {login}, авторизован! Токен - {token}")
    else:
        return make_response("Данные указаны неверно!")

# ------------------------------------------------------------

# просмотр ссылок

# возврат полной ссылки  (зарегистрированному пользователю)
@app.route("/get_link_user", methods=['POST'])
@jwt_required()
def get_link_user():
    login = str(get_jwt_identity())
    short_link = str(request.json.get("short_link", None))
    user = isUser(cursor, conn, login)
    link = getLink(cursor, conn, short_link)
    if link != None:
        if user[1] == link[1] and link[4] == 'private':
            if short_link == link[3]:
                print(link[3])
                return red(short_link)
            else:
                return make_response("Такой ссылки нет!")
        else:
            if short_link == link[3]:
                return red(short_link)
            else:
                return make_response("Такой ссылки нет или она вам недоступна!")
    else:
        return make_response("Ссылки нет в базе данных!")

# возврат полной ссылки  (незарегистрированному пользователю)
@app.route("/get_link", methods=['POST'])
def get_link():
    short_link = str(request.json.get("short_link", None))
    link = getLink(cursor, conn, short_link)
    if link != None and link[4] == 'public':
        return red(short_link)
    else:
        return make_response("Такой ссылки нет или она вам недоступна!")

# возврат моих ссылок
@app.route("/get_your_links", methods=['POST'])
@jwt_required()
def get_your_links():
    login = str(get_jwt_identity())
    links = allLinksOfUser(cursor, conn, login)
    if links != []:
        return make_response(f"Все ваши сокращенные ссылки: \n {links}")
    else:
        return make_response("У вас нет ссылок!")

# ------------------------------------------------------------

# ФУНКЦИИ ДЛЯ ССЫЛОК

# добавление ссылки
@app.route("/add_link", methods=['POST'])
@jwt_required()
def add_link():
    login = str(get_jwt_identity())
    begin_link = str(request.json.get("begin_link", None))
    short_link = str(request.json.get('short_link'))
    count_of_redirection = 0
    if short_link == "": short_link = hashlib.md5(begin_link.encode()).hexdigest()[:random.randint(8,12)]
    access = 'public'
    addLinks(cursor, conn, login, begin_link, short_link, access, count_of_redirection)
    return make_response(f'Вы успешно добавили ссылку. Ваша короткая ссылка - {short_link}')

# удаление ссылки
@app.route("/del_link", methods=['POST'])
@jwt_required()
def del_link():
    login = str(get_jwt_identity())
    short_link = str(request.json.get("short_link", None))
    delLinks(cursor, conn, short_link, login)
    return make_response('Вы успешно удалили ссылку!')

# изменение сокращенной ссылки (псевдоним)
@app.route("/change_short_link", methods=['POST'])
@jwt_required()
def change_short_link():
    login = str(get_jwt_identity())
    old_short_link = str(request.json.get("old_short_link", None))
    new_short_link = str(request.json.get("new_short_link", None))
    changeShLinks(cursor, conn, old_short_link, new_short_link, login)
    return make_response('Вы успешно изменили сокращенную ссылку!')

# изменение доступа
@app.route("/change_access_link", methods=['POST'])
@jwt_required()
def change_access_link():
    login = str(get_jwt_identity())
    short_link = str(request.json.get("short_link", None))
    access = str(request.json.get("access", None))
    changeAccLinks(cursor, conn, short_link, access, login)
    return make_response('Вы успешно изменили доступ!')

# переход по ссылке
@app.route("/<short>", methods=['POST'])
def red(short):
    link = getLink(cursor, conn, short)
    short_link_kol = link[5]

    # вызов функции для подсчета посещения ссылки
    getLinkAndKol(cursor, conn, short, short_link_kol)
    print(link)
    return redirect(link[2])

# ------------------------------------------------------------

if __name__ == "__main__":
        app.run()
