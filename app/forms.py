from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, validators


class LoginForm(FlaskForm):
    email = StringField('email', validators=[validators.required(), validators.Length(min=6, max=50)])
    password = PasswordField('password', validators=[validators.required(), validators.Length(min=1, max=35)])


class SignupForm(FlaskForm):
    email = StringField('email', validators=[validators.required(), validators.Length(min=6, max=50)])
    password = PasswordField('password', validators=[validators.required(), validators.Length(min=1, max=35)])
    username = StringField('username', validators=[validators.required(), validators.Length(min=3, max=20)])
