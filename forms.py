from flask_wtf import FlaskForm
from wtforms.fields import EmailField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle")
    img_url = StringField("Blog Image URL")
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment")
    submit = SubmitField('Submit')
