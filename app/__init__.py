# Proj_parser/app/__init__.py

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object(Config)
app.config['dbconfig'] = Config.dbconfig
db = SQLAlchemy(app)
db.create_engine(Config.SQLALCHEMY_DATABASE_URI,{})

migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

from app.routes import app_blueprint
app.register_blueprint(app_blueprint)

