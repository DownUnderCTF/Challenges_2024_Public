from flask import request, jsonify, render_template, redirect, flash, current_app as app
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User, BlogPost
from .utils import merge, save_feedback_to_disk
import os
import json

flag = os.getenv("flag")

# Not quite sure how many fields we want for this, lets just collect these bits now and increase them later. 
# Is it possible to dynamically add fields to this object based on the fields submitted by users?
class Feedback:
    def __init__(self):
        self.title = ""
        self.content = ""
        self.rating = ""
        self.referred = ""
        

@app.route('/')
def index():
    posts = BlogPost.query.filter_by(is_public=True).all()
    return render_template('index.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    if request.method == "POST":
        hashed_password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256')
        new_user = User(username=request.form.get("username"), password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    user = User.query.filter_by(username=request.form.get("username")).first()
    if user and check_password_hash(user.password, request.form.get("password")):
        login_user(user)
        return redirect("/")
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/dashboard")
def dashboard():
    posts = BlogPost.query.filter_by(author=current_user.id).all()
    return render_template("dashboard.html", posts=posts)


@app.route("/blog/<blog_id>")
def blog(blog_id):
    post = BlogPost.query.filter_by(id=int(blog_id)).first()
    if not post:
        flash("Blog post does not exist!")
        return redirect("/")
    return render_template("blog.html", post=post)


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
        return render_template("edit_blog.html", blog=blog)
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
    return render_template("create_post.html")


@app.route("/changelog", methods=["GET"])
def changelog():
    return render_template("changelog.html")

    
@app.route("/feedback")
@login_required
def feedback():
    return render_template("feedback.html")


@app.route("/save_feedback", methods=["POST"])
@login_required
def save_feedback():
    data = json.loads(request.data)
    feedback = Feedback()
    # Because we want to dynamically grab the data and save it attributes we can merge it and it *should* create those attribs for the object.
    merge(data, feedback)
    save_feedback_to_disk(feedback)
    return jsonify({"success": "true"}), 200

@app.route("/get_flag")
@login_required
def get_flag():
    if flag == "true":
        return "DUCTF{_cl455_p0lluti0n_ftw_}"
    else:
        return "Nope"

@app.route("/api/update_user_data")
@login_required
def update_user_data():
    return "Coming Soon..."