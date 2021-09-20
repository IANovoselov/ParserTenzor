# Proj_parser/config.py

import os
basedir = os.path.abspath(os.path.dirname(__file__))
postgres_local_base = 'postgresql://postgres:qwerty@localhost:5432/'
database_name = 'parser'


class Config(object):
    """Конфигурационные параметры"""
    SECRET_KEY = 'secret_key'
    DEBUG = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    dbconfig = {'host': 'localhost',
                'port': '5432',
                'user': 'postgres',
                'password': 'qwerty',
                'dbname': 'parser', }
    SQLALCHEMY_DATABASE_URI = 'postgresql://'+dbconfig['user'] + ':' + dbconfig['password'] + '@' + dbconfig['host'] + \
                              ':' + dbconfig['port'] + '/' + dbconfig['dbname']
    BCRYPT_LOG_ROUNDS = 4  # Для хэширования паролей

