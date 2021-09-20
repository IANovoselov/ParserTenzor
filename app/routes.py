# Proj_parser/app/routes.py

from flask import Blueprint, request, make_response, jsonify, copy_current_request_context
from flask.views import MethodView
from threading import Thread
from app import bcrypt, db, app
from app.models import User, UseDataBase, ConnectionErrors, Article, LogoutTokens

app_blueprint = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    Регистрация пользователя
    Выполняется проверка на наличие пользователя с таким email в системе.
    Если пользователь не зарегестрирован ранее, то выполняется его регистрация и генерация JWT токена.
    Если такой пользователь уже существует, то формируется ответ с просьбой войти в систему.
    """

    def post(self):
        # получение post-запроса
        post_data = request.get_json()

        # проверка существует ли уже такой пользователь
        try:
            with UseDataBase(app.config['dbconfig']) as cursor:
                _SQL = """SELECT * FROM users WHERE email = '{}'""".format(post_data.get('email'))
                cursor.execute(_SQL)
                content = cursor.fetchall()

        except Exception as err:
            responseObject = {
                'status': 'Ошибка',
                'message': '{}'.format(str(err))
            }
            return make_response(jsonify(responseObject)), 401
        # если пользователя нет - выполнить регситрацию и сгенерировать JWT токен
        if not content:
            user = User(email=post_data.get('email'), password=post_data.get('password'))
            try:
                with UseDataBase(app.config['dbconfig']) as cursor:
                    _SQL = """INSERT INTO users
                    (email, password)
                    VALUES
                    (%s, %s)"""
                    cursor.execute(_SQL, (user.email,
                                          user.password))

                # в слуае успешного входа
                responseObject = {
                    'status': 'Успешно',
                    'message': 'Регистрация осуществлена. Теперь можно войти в систему.',
                }
                return make_response(jsonify(responseObject)), 201
            # обработка исключений
            except ConnectionErrors:
                responseObject = {
                    'status': 'Ошибка',
                    'message': 'Проверьте настройки базы данных.'
                }
                return make_response(jsonify(responseObject)), 401

            except Exception as err:
                responseObject = {
                    'status': 'Ошибка',
                    'message': '{}'.format(str(err))
                }
                return make_response(jsonify(responseObject)), 401

        else:
            responseObject = {
                'status': 'Ошибка',
                'message': 'Пользователь уже зарегестрирован. Выполните вход в систему',
            }
            return make_response(jsonify(responseObject)), 202


class LoginAPI(MethodView):
    """
    Вход пользователя в систему
    Проверяется пользователь, пароль и его хэш
    Обновляется JWT токен
    """
    def post(self):
        # получение post-запроса
        post_data = request.get_json()

        try:
            with UseDataBase(app.config['dbconfig']) as cursor:
                _SQL = """SELECT * FROM users WHERE email = '{}'""".format(post_data.get('email'))
                cursor.execute(_SQL)
                content = cursor.fetchall()
                password_hash = content[0][2]
                user_id = content[0][0]

                # инициализация пользователя
                user = User(email=post_data.get('email'), password=post_data.get('password'))

            if content and bcrypt.check_password_hash(
                password_hash, post_data.get('password')
            ):

                auth_token = user.encode_auth_token(user_id)
                if auth_token:
                    responseObject = {
                        'status': 'Успешно',
                        'message': 'Вход в систему осуществлён',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'ошибка',
                    'message': 'пользователя не существует или неверный пароль'
                }
                return make_response(jsonify(responseObject)), 404

        except Exception as err:
            responseObject = {
                'status': 'Ошибка',
                'message': '{}'.format(str(err))
            }
            return make_response(jsonify(responseObject)), 500


class GetArticle(MethodView):
    """
    Парсинг статьи, отправка клиенту и запись в базу данных с использованием потоков
    """
    def get(self):
        @copy_current_request_context
        def log_article(user_id, article):
            try:

                with UseDataBase(app.config['dbconfig']) as cursor:
                    _SQL = """INSERT INTO articles
                     (user_id, date, title, author, text)
                     VALUES
                     (%s, %s, %s, %s, %s)"""
                    cursor.execute(_SQL, (user_id,
                                          user_article['date'],
                                          user_article['title'],
                                          user_article['author'],
                                          user_article['text']))
            except Exception as err:
                responseObject = {
                    'status': 'Ошибка',
                    'message': '{}'.format(str(err))
                }
                return make_response(jsonify(responseObject)), 500

        # Получение заголовков авторизации
        auth_header = request.headers.get('Authorization')
        article_link = request.get_json().get('link')
        if auth_header:
            try:
                # Получение токена
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'Ошибка',
                    'message': 'Токен отсутсвует в заголовках'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = None
        if auth_token:
            user_id = User.decode_auth_token(auth_token)
            print(type(user_id))
            # Валидация ID пользователя тип - integer
            if isinstance(user_id, int):
                user_article = Article(link=article_link).finde()
                t = Thread(target=log_article, args=(user_id, user_article))
                t.start()

                responseObject = user_article

                return make_response(jsonify(responseObject)), 200

            responseObject = {
                'status': 'Ошипбка',
                'message': user_id
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'ошибка',
                'message': 'Токен не прошёл валидацию'
            }
            return make_response(jsonify(responseObject)), 401


class LogoutAPI(MethodView):
    """
    Выход из системы
    Тоекн отмечается как неактивный
    """
    def post(self):
        # полуение токена из запроса
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            user_id = User.decode_auth_token(auth_token)
            if isinstance(user_id, int):
                # Запись токена в БД использованных токенов
                logout_token = LogoutTokens(token=auth_token)
                try:
                    print(type(auth_token))
                    with UseDataBase(app.config['dbconfig']) as cursor:
                        _SQL = """INSERT INTO logout_tokens
                         (token)
                         VALUES
                         (%s)"""
                        cursor.execute(_SQL, (auth_token,))
                except Exception as err:
                    responseObject = {
                        'status': 'Ошибка БД',
                        'message': '{}'.format(str(err))
                    }
                    return make_response(jsonify(responseObject)), 500
                responseObject = {
                    'status': 'Успешно',
                    'message': 'Вы вышли из системы'
                }
                return make_response(jsonify(responseObject)), 401
            else:
                responseObject = {
                    'status': 'Ошибка',
                    'message': 'Ошибка пользователя'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'Ошибка',
                'message': 'Токен не прошёл валидаию'
            }
            return make_response(jsonify(responseObject)), 403


# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
article_view = GetArticle.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
app_blueprint.add_url_rule(
    '/register',
    view_func=registration_view,
    methods=['POST']
)
app_blueprint.add_url_rule(
    '/login',
    view_func=login_view,
    methods=['POST']
)
app_blueprint.add_url_rule(
    '/article',
    view_func=article_view,
    methods=['GET']
)
app_blueprint.add_url_rule(
    '/logout',
    view_func=logout_view,
    methods=['POST']
)