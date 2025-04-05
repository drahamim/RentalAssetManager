from flask_wtf import FlaskForm
from wtforms import FileField, SelectField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from flask_wtf.file import FileRequired, FileAllowed
import pytz


class SettingsForm(FlaskForm):
    timezone = SelectField('Timezone', choices=[
                           (tz, tz) for tz in pytz.all_timezones])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


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
    # roles = SelectField('Roles', choices=[])


class UploadForm(FlaskForm):
    data_type = SelectField('Data Type', choices=[
        ('staff', 'Staff'), ('assets', 'Assets')])
    file = FileField('File', validators=[
        FileRequired(), FileAllowed(['csv'], 'CSV files only!')])
    submit = SubmitField('Upload', render_kw={
        'class': 'btn btn-primary', 'disabled': True})
