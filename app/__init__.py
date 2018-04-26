from flask import Flask
import os

app = Flask(__name__)
app.config.from_object('config')
app.secret_key = os.urandom(12)

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

from app import views
