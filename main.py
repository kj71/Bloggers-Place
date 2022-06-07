from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import RegisterForm, LoginForm, CommentForm, CreatePostForm
from flask_gravatar import Gravatar
from urllib.parse import urlparse, urljoin
from functools import wraps
import requests
import smtplib
import re
from email.message import EmailMessage
import os
import psycopg2

my_email = os.environ.get('Email')
password = os.environ.get('Password')


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
uri = os.environ.get("DATABASE_URL")  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=80,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def admin_only(fun):
    @wraps(fun)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return fun(*args, **kwargs)
        else:
            return abort(403)

    return wrapper


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
    comments = relationship('Comment', back_populates='post')


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    author = relationship("User", back_populates="comments")
    post = relationship("BlogPost", back_populates="comments")


db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.order_by(BlogPost.date.desc()).all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user_form = RegisterForm()
    if user_form.validate_on_submit():
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            flash('Account with this email already exists.')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password=request.form['password'], method='pbkdf2:sha256',
                                                 salt_length=8)
        new_user = User(
            email=request.form['email'],
            password=hashed_password,
            name=request.form['name']
        )

        db.session.add(new_user)
        db.session.commit()

        msg = EmailMessage()
        msg['Subject'] = f'Welcome to Bloggers\' Place'
        msg['From'] = os.environ.get('Email')
        msg['To'] = request.form['email']
        message = f'''
                    Hi, <b>{request.form["name"]}</b>, Thanks for registering at Bloggers' Place.We’re glad to have you as part of our community.
                    <p>
                    Here are a few things you can do to get started:
                    <ul>
                    <li>Express your views on a topic by creating a blog.</li>
                    <li>Explore the site and get to know the other members.</li>
                    <li>Check out the latest blog posts and leave your comments.</li>
                    </ul>
                    </p>
                    I hope you enjoy your time on the site!<br>
                    Sincerely,<br>
                    Kavya Jain
                    '''
        msg.set_content(message)
        msg.add_alternative(message, 'html')
        connection = smtplib.SMTP_SSL("smtp.mail.yahoo.com", port=465)
        connection.login(user=my_email, password=password)
        connection.send_message(msg)
        connection.quit()

        return redirect(url_for('login'))
    return render_template("register.html", form=user_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=request.form['email']).first()
        if user == None:
            flash('User with given Email not found')
            return redirect(url_for('login'))
        if check_password_hash(user.password, request.form['password']) == False:
            flash('Incorrect Password.')
            return redirect(url_for('login'))
        login_user(user)
        next = request.args.get('next')
        if not is_safe_url(next):
            return abort(400)
        return redirect(next or url_for('login'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        new_comment = Comment(
            text=request.form['comment'],
            author_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        msg = EmailMessage()
        msg['Subject'] = f'Message at Bloggers\'s Place by {request.form["name"]}'
        msg['From'] = os.environ.get('Email')
        msg['To'] = os.environ.get('Email2')
        message = f'''
            Hi, Buddy, Here is a message for you by {request.form["name"]}:
            \"{request.form['message']}\"
            You can reply at {request.form['email']}
            '''
        msg.set_content(message)
        connection = smtplib.SMTP_SSL("smtp.mail.yahoo.com", port=465)
        connection.login(user=my_email, password=password)
        connection.send_message(msg)
        connection.quit()
        flash('Message sent successfully!!!')
        return redirect(url_for('contact'))
    return render_template('contact.html')


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
def edit_post(post_id, methods=['GET', 'POST']):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == '__main__':
    app.run(debug=True)
