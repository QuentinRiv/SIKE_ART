
import requests
from numpy import random
from functools import wraps
from flask import render_template, url_for, request, redirect
from flask import flash, Blueprint

from flask_login import LoginManager, login_required
from flask_login import login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from flask import current_app as app

from appli.info.mysike import SIKE_compute_pk, server_address
from appli import db
from appli.info.db_func import register_db,  generate_otk, add_db, get_token
from appli.info.classes import User

login_bp = Blueprint('login_bp', __name__,
                     template_folder='templates',
                     static_folder='static')


login_manager = LoginManager()
login_manager.login_view = 'login'     # Page name to log in
login_manager.login_message = u"Sorry ! You cannot access to this page..."
login_manager.init_app(app)


def still_connected(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if current_user.is_authenticated:
            headers = {'x-access-tokens': get_token(current_user.name)}
            response = requests.get(server_address + "/still_connected",
                                    headers=headers)
            if response.status_code == 401:
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorator


def fill_db(name, email=None, password=None):
    if not email:
        email = name+"@etu.unige.ch"
    if not password:
        password = "123"
    generate_otk(name)
    private_key = random.randint(1, 100)
    public_key_rec = SIKE_compute_pk(private_key, side="receiver")
    register_db(name, public_key_rec, side="receiver")
    public_key_ini = SIKE_compute_pk(private_key, side="initiator")
    register_db(name, public_key_ini, side="initiator")

    # create a new user with the form data.
    # Hash the password so the plaintext version isn't saved.
    new_user = User(email=email,
                    name=name,
                    password=generate_password_hash(
                        password, method='sha256'),
                    privID=private_key)

    add_db(new_user, "User {}".format(new_user.name))

    requests.post(server_address + '/signup',
                  json={'user': name, 'email': email, 'password': password})

    return 0


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table,
    # use it in the query for the user
    return User.query.get(int(user_id))


# Template for the login
@login_bp.route('/login')
def login():
    return render_template('login.html')


# Login page
@login_bp.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it,
    # and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        # if the user doesn't exist or password is wrong, reload the page
        return redirect(url_for('login_bp.login'))

    # if the above check passes, then we know
    # the user has the right credentials
    login_user(user, remember=remember)
    r = requests.post(server_address + '/login', auth=(email, password))
    user.token = r.json()['token']
    db.session.commit()
    return redirect(url_for('message_bp.messenger'))


# When loging out, redirect to the index page
@login_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('info_bp.start'))


@login_bp.route('/signup')
def signup():
    return render_template('signup.html')


@login_bp.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    username = request.form.get('name')
    password = request.form.get('password')

    # if this returns a user, then the email already exists in database
    user = User.query.filter_by(email=email).first()

    # if a user is found, we want to redirect back to signup page
    # so user can try again
    if user:
        flash('Email address already exists')
        return redirect(url_for('login_bp.signup'))

    fill_db(username, email, password)

    return redirect(url_for('login_bp.login'))
