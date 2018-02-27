from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, SelectField
from wtforms.validators import ValidationError, DataRequired, EqualTo, IPAddress
from app.models import User



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')


class EditorIp(FlaskForm):
    name_inter = SelectField('Name interface', coerce=str)
    new_addr = StringField('New ip', validators=[IPAddress('Should be ip address'), DataRequired('Please input ip address')])
    mask = StringField('New netmask', validators=[IPAddress('Should be netmask'), DataRequired('Please input mask address')])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Edit')
        
                    
