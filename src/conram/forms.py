from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
import pytz


class SettingsForm(FlaskForm):
    timezone = SelectField('Timezone', choices=[
                           (tz, tz) for tz in pytz.all_timezones])


class LoginForm(FlaskForm):
    username = SelectField('Username', choices=[])
    password = SelectField('Password', choices=[])
    submit = SelectField('Login', choices=[('login', 'Login')])


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name')
    email = StringField('Email')
    submit = SubmitField('Register')


class UpdateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password')
    confirm_password = PasswordField(
        'Confirm Password', validators=[EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name')
    email = StringField('Email', render_kw=(dict(value='email')))