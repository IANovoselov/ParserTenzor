# Proj_parser/app/models.py

import jwt
import re
import datetime
import psycopg2
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from app import app, db, bcrypt
from flask import make_response, jsonify


# Сущности - таблицы базы данных
class User(db.Model):
    """ Модель сущности Пользователь """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()

    def encode_auth_token(self, user_id):
        """
        Генерация JWT токена
        """
        try:
            payload = {
                # время жизни токена 30 минут
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Валидация токена
        Декодирование и возвращение ID пользователя
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            logout = LogoutTokens.check_blacklist(auth_token)
            if logout:
                return 'Вы не вошли в систему' # возвращаем строку
            else:
                return payload['sub'] # возвращаем число
        except Exception as err:
            responseObject = {
                'status': 'Ошибка',
                'message': '{}'.format(str(err))
            }
            return make_response(jsonify(responseObject)), 401

class Article(db.Model):
    """ Модель сущности Статьи """
    __tablename__ = "articles"

    id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    date = db.Column(db.String, nullable=False)
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    text = db.Column(db.String, nullable=True)

    def __init__(self, link):
        self.link = link
        self.out_put = []
        self.article = {'date': '', 'author': '', 'title': '', 'text': ''}
        self.response = requests.get(self.link, headers={'User-Agent': UserAgent().chrome})
        self.response.encoding = 'utf-8'
        self.soup = BeautifulSoup(self.response.text, 'lxml')

    def content_p(self, div):
        """информаия, содержащаяся в параграфах"""
        for p in div.find_all('p'):
            self.out_put.append(p.text)
        return self.out_put

    def finde(self):
        """главный метод, осуществляет поиск таких эдементов разметки div"""
        answer = []
        answer.extend(self.content_p(self.soup.find('div', {"class": "b-topic__content"})))

        self.article['date'] = self.soup.find('time')['datetime'].strip()
        self.article['title'] = self.soup.title.text.strip()
        self.article['author'] = answer[-1].strip()
        text_string = ''.join(answer[:-1])
        self.article['text'] = text_string.strip()
        return self.article


# Менеджер контектса для работы с БД с помощью сырых запросов
class ConnectionErrors(Exception):
    pass


class SQLError(Exception):
    pass


class UseDataBase:

    def __init__(self, config: dict) -> None:
        self.configuration = config

    def __enter__(self):
        try:
            self.conn = psycopg2.connect(**self.configuration)
            self.cursor = self.conn.cursor()
            return self.cursor
        except psycopg2.InterfaceError as err:
            raise ConnectionErrors(err)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.commit()
        self.cursor.close()
        self.conn.close()
        if exc_type is psycopg2.ProgrammingError:
            raise SQLError(exc_val)
        elif exc_type:
            raise exc_type(exc_val)


class LogoutTokens(db.Model):
    """
    Модель сущности, хранящей неактивне токены
    """
    __tablename__ = 'logout_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)

    def __init__(self, token):
        self.token = token

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # Проверка, находится ли токен в списке неактивных
        try:
            with UseDataBase(app.config['dbconfig']) as cursor:
                _SQL = """SELECT id FROM logout_tokens WHERE token = '{}'""".format(auth_token)
                cursor.execute(_SQL)
                content = cursor.fetchall()

        except Exception as err:
            responseObject = {
                'status': 'Ошибка',
                'message': '{}'.format(str(err))
            }
            return make_response(jsonify(responseObject)), 401

        if content:
            return True
        else:
            return False