from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class ChangePasswordForm(Form):
    old_passwd = PasswordField('Old Password', validators=[Required()])
    new_passwd = PasswordField('New Password', validators=[Required()])
    submit = SubmitField('OK')

class ForgetPasswordForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), 
                                             Email()])
    submit = SubmitField('OK')
class ChangeEmailSetForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('OK')

class ChangeEmailPasswordConfirmForm(Form):
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('OK')

class FPNewPasswordForm(Form):
    password = PasswordField('Password', validators=[
            Required(), EqualTo('password2', message='Password must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('OK')

class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
