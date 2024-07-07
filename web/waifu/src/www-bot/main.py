from flask import Flask, Response, render_template, request, session, redirect
from functools import wraps
import secrets
import urllib.parse as urlparse
import bot
import threading

app = Flask(__name__, static_folder='static/', static_url_path='/')
app.secret_key = secrets.token_bytes(64)
threading.Thread(target=bot.bot_worker, daemon=True).start()

def set_session() -> tuple[str, str]:
    session["csrf"] = secrets.token_hex(8)
    return session["csrf"]


def return_response(msg: str = "", error: str = "") -> Response:
    csrf = session["csrf"]
    queue = [t[0] for t in list(bot.bot_queue.queue)]
    if error:
        return render_template("index.html", error=error, csrf=csrf, queue=queue)
    elif msg:
        return render_template("index.html", msg=msg, csrf=csrf, queue=queue)
    return render_template("index.html", csrf=csrf, queue=queue)


def check_csrf(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        try:
            check_csrf = request.form.get("csrf", "") == session["csrf"]
            if not check_csrf:
                set_session()
                return return_response(error="Invalid CSRF sent!")
        except:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_func

@app.route("/", methods=["GET"])
def index():
    set_session()
    return return_response()


@app.route("/sendbot", methods=["POST"])
@check_csrf
def send_bot():
    url_path = request.form.get('urlPath', None)
    if url_path is None:
        return return_response(error="No URL was sent!")

    if not url_path[0] == '/':
        return return_response(error="Url path must start with '/'")
    
    bot.bot_queue.put((url_path,))
    return return_response(msg="The request has been queued!")


@app.route("/clearqueue", methods=["POST"])
@check_csrf
def clear_queue():
    while not bot.bot_queue.empty():
        try:
            bot.bot_queue.get(block=False)
        except Exception:
            continue
        bot.bot_queue.task_done()
    return return_response(msg="Queue has been cleared!")

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)