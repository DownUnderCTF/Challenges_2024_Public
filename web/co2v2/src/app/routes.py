from flask import request, url_for, jsonify, render_template, redirect, flash, g, current_app as app
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User, BlogPost
from .utils import merge, save_feedback_to_disk, generate_random_string
import os
import json
from jinja2 import Environment, select_autoescape, PackageLoader
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import requests
import hashlib
import random
from flask_cors import CORS

CORS(app)

# Secret used to generate a nonce to be used with the CSP policy 
SECRET_NONCE = generate_random_string()
# Use a random amount of characters to append while generating nonce value to make it more secure
RANDOM_COUNT = random.randint(32,64)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per minute"]
)

TEMPLATES_ESCAPE_ALL = True
TEMPLATES_ESCAPE_NONE = False

# Not quite sure how many fields we want for this, lets just collect these bits now and increase them later. 
# Is it possible to dynamically add fields to this object based on the fields submitted by users?
class Feedback:
    def __init__(self):
        self.title = ""
        self.content = ""
        self.rating = ""
        self.referred = ""

class jEnv():
    """Contains the default config for the Jinja environment. As we move towards adding more functionality this will serve as the object that will
    ensure the right environment is being loaded. The env can be updated when we slowly add in admin functionality to the application.
    """
    def __init__(self):
        self.env = Environment(loader=PackageLoader("app", "templates"), autoescape=TEMPLATES_ESCAPE_ALL)

template_env = jEnv()


def generate_nonce(data):
    nonce = SECRET_NONCE + data + generate_random_string(length=RANDOM_COUNT)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(nonce.encode('utf-8'))
    hash_hex = sha256_hash.hexdigest()
    g.nonce = hash_hex
    return hash_hex

@app.before_request
def set_nonce():
    generate_nonce(request.path)

@app.after_request
def apply_csp(response):
    nonce = g.get('nonce')
    csp_policy = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://ajax.googleapis.com; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"script-src-attr 'self' 'nonce-{nonce}'; " 
        f"connect-src *; "
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Not allowed.')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.data['role'] != 'admin':
            flash('Not allowed.')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    posts = BlogPost.query.filter_by(is_public=True).all()
    template = template_env.env.get_template("index.html")    
    return template.render(posts=posts, current_user=current_user, nonce=g.nonce)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    if request.method == "POST":
        hashed_password = generate_password_hash(request.form.get("password"), method='sha256')
        new_user = User(username=request.form.get("username"), password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template("register.html", nonce=g.nonce)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    user = User.query.filter_by(username=request.form.get("username")).first()
    if user and check_password_hash(user.password, request.form.get("password")):
        login_user(user)
        return redirect("/")
    return render_template("login.html", nonce=g.nonce)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", nonce=g.nonce)


@app.route("/dashboard")
@login_required
def dashboard():
    posts = BlogPost.query.filter_by(author=current_user.id).all()
    template = template_env.env.get_template("dashboard.html")
    return template.render(posts=posts, current_user=current_user, nonce=g.nonce)


@app.route("/blog/<blog_id>")
def blog(blog_id):
    post = BlogPost.query.filter_by(id=int(blog_id)).first()
    if not post:
        flash("Blog post does not exist!")
        return redirect("/")
    template = template_env.env.get_template("feedback.html")
    return template.render(post=post, nonce=g.nonce, current_user=current_user)


@app.route("/edit/<blog_id>", methods=["GET", "POST"])
@login_required
def edit_blog_post(blog_id):
    blog = BlogPost.query.filter_by(id=blog_id).first()
    if request.method == "POST":
        blog.title = request.form.get("title")
        blog.content = request.form.get("content")
        blog.is_public = bool(int(request.form.get("public"))) if request.form.get("public") else False
        db.session.add(blog)
        db.session.commit()
        return redirect(f"/blog/{str(blog.id)}")
    if blog and current_user.id == blog.author:
        return render_template("edit_blog.html", blog=blog, nonce=g.nonce)
    else:
        return redirect("/403")

@app.route("/create_post", methods=["GET", "POST"])
@login_required
def create_post():
    if request.method == "POST":
        post = BlogPost(title=request.form.get("title"), content=request.form.get("content"), author=current_user.id)
        post.is_public = bool(int(request.form.get("public"))) if request.form.get("public") else False
        db.session.add(post)
        db.session.commit()
        return redirect("/dashboard")
    template = template_env.env.get_template("create_post.html")
    return template.render(nonce=g.nonce, current_user=current_user)


@app.route("/changelog", methods=["GET"])
def changelog():
    template = template_env.env.get_template("changelog.html")
    return template.render(nonce=g.nonce)


@app.route("/feedback")
@login_required
def feedback():
    template = template_env.env.get_template("feedback.html")
    return template.render(nonce=g.nonce, current_user=current_user)


@app.route("/save_feedback", methods=["POST"])
@login_required
def save_feedback():
    data = json.loads(request.data)
    feedback = Feedback()
    # Because we want to dynamically grab the data and save it attributes we can merge it and it *should* create those attribs for the object.
    merge(data, feedback)
    save_feedback_to_disk(feedback)
    return jsonify({"success": "true"}), 200


@app.route("/api/update_user_data")
@login_required
def update_user_data():
    return "Coming Soon..."

# Future Admin routes - FOR TEST ENVIRONMENT ONLY
@app.route("/admin/update-accepted-templates", methods=["POST"])
@login_required
def update_template():
    data = json.loads(request.data)
    # Enforce strict policy to filter all expressions
    if "policy" in data and data["policy"] == "strict":
        template_env.env = Environment(loader=PackageLoader("app", "templates"), autoescape=TEMPLATES_ESCAPE_ALL)
    # elif "policy" in data and data["policy"] == "lax":
    #     template_env.env = Environment(loader=PackageLoader("app", "templates"), autoescape=TEMPLATES_ESCAPE_NONE)
    # TO DO: Add more configurations for allowing LateX, XML etc. to be configured in app
    return jsonify({"success": "true"}), 200


@app.route("/api/v1/report")
@limiter.limit("6 per minute")
def report():
    resp = requests.post(f'{os.getenv("XSSBOT_URL", "http://xssbot:8000")}/visit', json={'url':
        os.getenv("APP_URL", "http://co2v2:1337")
    }, headers={
        'X-SSRF-Protection': '1'
    })
    print(resp.text)
    return jsonify(status=resp.status_code)
