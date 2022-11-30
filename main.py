from flask import Flask, request, redirect, jsonify, make_response
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
import sqlite3, uuid, hashlib, random
from werkzeug.security import generate_password_hash,check_password_hash

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# # создание таблицы с юзерами
#
# cursor.execute('''CREATE TABLE IF NOT EXISTS "users" (
#     "id" INTEGER NOT NULL UNIQUE,
#     "login" TEXT NOT NULL UNIQUE,
#     "password" TEXT NOT NULL,
#     PRIMARY KEY("id" AUTOINCREMENT)
#     );''')
# connect.commit()
#
# # создание таблицы с ссылками
#
# cursor.execute('''CREATE TABLE IF NOT EXISTS "links" (
#     "id" INTEGER UNIQUE NOT NULL,
#     "user_id" INTEGER NOT NULL REFERENCES users (id),
#     "begin_link" TEXT NOT NULL,
#     "short_link" TEXT NOT NULL,
#     "access" TEXT NOT NULL,
#     "click_on_link" INTEGER NOT NULL,
#     PRIMARY KEY("id" AUTOINCREMENT)
#     );''')
# connect.commit()

app = Flask(__name__)
app.config["SECRET_KEY"] = "dfghjkllkjh313"
jwt = JWTManager(app)

def convertList(link):
    str = ''
    for i in link:
        str += i+"\n"
    return str

@app.route('/register', methods = ["post"])
def reg():
    print('123')
    if request.method == 'POST':
        login = str(request.json.get('login', None))
        password = str(request.json.get('password', None))
        return make_response(regis_user(cursor, conn, login, password))

@app.route('/autho', methods = ["post"])
def authorize():
    if request.method == 'POST':
        login = str(request.json.get('login', None))
        password = str(request.json.get('password', None))
        return make_response(auth_user(cursor, conn, login, password))

def regis_user(cursor, connect, login, password):
    proverka = cursor.execute('SELECT login FROM users').fetchall()
    users = []
    for item in proverka:
        users.append(item[0])
    if (login in users):
        return "Такой пользователь уже есть"
    else:
        cursor.execute('INSERT INTO users(login, password) VALUES(?, ?)', (login, password))
        connect.commit()
        return "Вы успешно зарегистрировались"

def auth_user(cursor, login, password):
    auth = cursor.execute('SELECT login, password FROM users').fetchall()
    users = dict()
    for item in auth:
        users[item[0]] = item[1]
    if (login in users.keys() and password == users.get(login)):
        return "Вы успешно авторизовались!"
    else:
       return "Данные указаны неверно!"

if __name__ == "__main__":
        app.run()
