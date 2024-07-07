from . import db, login_manager
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    data = db.Column(db.JSON, nullable=False, default={"role": "user"})

    def __init__(self, username, password):
        self.username = username
        self.password = password


class BlogPost(db.Model):
    __tablename__ = "blogpost"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(300), nullable=False)
    content = db.Column(db.Text)
    author = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_public = db.Column(db.Boolean)

    def __repr__(self):
        return f"{self.title}"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))