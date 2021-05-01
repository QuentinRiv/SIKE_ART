import requests
from numpy import random

from flask import render_template
from flask import send_from_directory, url_for

from flask_login import current_user
from werkzeug.security import generate_password_hash

from flask import current_app as app

from .mysike import eA, eB, p, A, PA, PB, QA, QB
from .mysike import SIKE_compute_pk, server_address

from .classes import db, User, Group, Party, OneTimeKey
from .db_func import register_db,  generate_otk, add_db
from .db_func import get_members
from .db_func import get_id, names_n_group


def fill_db(name, email=None, password=None):
    if not email:
        email = name+"@etu.unige.ch"
    if not password:
        password = "123"
    generate_otk(name)
    private_key = random.randint(1, 2**eA)
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


# @app.before_first_request
# def before_first_request():
#     if not os.path.isfile('./client.db'):
#         db.create_all()
#         for name in ["Quentin", "Bob", "Charlie", "Dom", "Eve"]:
#             fill_db(name)


# Starting page
@app.route('/')
def start():
    return render_template('index.html')


# Return the thesis PDF
@app.route('/paper')
def paper():
    return send_from_directory('static', 'paper.pdf')


# Information about the partner 'partner'
@app.route('/partnerinfo/<partner>')
def partnerinfo(partner):
    names, groupnames = names_n_group(current_user.name)
    members = []
    members_id = {}
    partner_id = ""
    if partner in groupnames:
        members = get_members(partner)
        for member in members:
            members_id[member] = get_id(member, string=True)
        partner_id = get_id(partner, string=True)
    else:
        partner_id = get_id(partner, string=True)
    return {'members': members, 'members_id': members_id, 'id': partner_id}


@app.route('/profile/<user>')
def profile(user):
    party = Party.query.filter_by(name=current_user.name, target=user).first()
    return render_template('profile.html', name=user,
                           id=party.id, public_key=party.publicID)


# Not found Error 404
@app.errorhandler(404)
def page_not_found(error):
    return render_template('not_found.html')


@app.route('/info')
def info():
    return render_template('info.html',
                           parameters={"eA": eA, "eB": eB, "p": p,
                                       "PA": PA, "PB": PB, "QA": QA,
                                       "QB": QB, "A": A})


# Delete everything
@app.route('/delete_all')
def delete_all():
    db.drop_all()
    db.create_all()
    requests.get(server_address + "/delete_all/")
    return "Done", 200


@app.route('/info_database')
def info_database():
    infos = ""
    parties = Party.query.all()
    for party in parties:
        infos += str(party.id) + " : " + party.name + '->' + party.target + \
            " => " + repr(party.publicID) + "\n"
    infos += "\n******************************\n"

    groups = Group.query.all()
    for group in groups:
        infos += str(group.id) + " : " + group.groupname + \
            " => " + group.members + "\n"

    infos += "\n******************************\n"
    otks = OneTimeKey.query.all()
    for otk in otks:
        infos += str(otk.id) + " : " + otk.owner + \
            " => " + str(otk.serverID) + "\n"
    infos += "\n******************************\n"

    users = User.query.all()
    for user in users:
        infos += str(user.id) + " : " + user.name + "\n"

    return infos


def has_no_empty_params(rule):
    defaults = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()
    return len(defaults) >= len(arguments)


@app.route("/site-map")
def site_map():
    links = []
    for rule in app.url_map.iter_rules():
        # Filter out rules we can't navigate to in a browser
        # and rules that require parameters
        if "GET" in rule.methods and has_no_empty_params(rule):
            url = url_for(rule.endpoint, **(rule.defaults or {}))
            links.append((url, rule.endpoint))
    # links is now a list of url, endpoint tuples
