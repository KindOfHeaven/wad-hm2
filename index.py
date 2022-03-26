from flask import Flask, render_template, redirect, make_response, request, flash
from pymongo import MongoClient

import hashlib
import hmac

SECRET_KEY = b"s3cr3ts4lt"

client = MongoClient('localhost', 27017)
db = client.homework2

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        username = request.cookies.get('username')
        token = request.cookies.get('token')

        if hmac.compare_digest(
            hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest(),
            token
        ):
            return redirect('/profile')
        return render_template('index.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        passwordHash = hmac.new(SECRET_KEY, password.encode(), hashlib.sha256).hexdigest()

        user = db.users.find_one({ 'username': username })

        if (user and hmac.compare_digest(passwordHash, user['password'])):
            resp = make_response(redirect('/profile'))
            resp.set_cookie('username', username)
            resp.set_cookie('token', hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest())
            return resp
        else:
            flash(f'Invalid credentials!')
        return redirect('/') 

@app.route('/profile')
def profile():
    username = request.cookies.get('username')
    token = request.cookies.get('token')

    if not hmac.compare_digest(
        hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest(),
        token
    ):
        return render_template('error.html', error = '403 Forbidden')
    return render_template('profile.html', username = username)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        username = request.cookies.get('username')
        token = request.cookies.get('token')

        if hmac.compare_digest(
            hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest(),
            token
        ):
            return redirect('/profile')
        return render_template('signup.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        passwordHash = hmac.new(SECRET_KEY, password.encode(), hashlib.sha256).hexdigest()
        if (db.users.find_one({ 'username': username })):
            flash(f'The user with this username already exists!')
            return redirect('/signup')
        else:
            document = {
                'username': username,
                'password': passwordHash
            }

            db.users.insert_one(document)
            return render_template('signup-thanks.html', username = username)    

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie('username', '')
    resp.set_cookie('token', '')
    return resp


app.run(host="localhost", port=5001, debug=True)