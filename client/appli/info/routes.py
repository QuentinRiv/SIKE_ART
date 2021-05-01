import requests
from numpy import random

from flask import render_template, Blueprint
from flask import send_from_directory

from flask_login import current_user
from werkzeug.security import generate_password_hash

from .mysike import eA, eB, p, A, PA, PB, QA, QB
from .mysike import SIKE_compute_pk, server_address

from .classes import db, User, Group, Party, OneTimeKey
from .db_func import register_db,  generate_otk, add_db
from .db_func import get_members
from .db_func import get_id, names_n_group


info_bp = Blueprint('info_bp', __name__,
                    template_folder='templates',
                    static_folder='static',
                    static_url_path='/appli/info/static')


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


# Starting page
@info_bp.route('/')
def start():
    return render_template('index.html')


# Return the thesis PDF
@info_bp.route('/paper')
def paper():
    return send_from_directory('static', 'paper.pdf')


# Information about the partner 'partner'
@info_bp.route('/partnerinfo/<partner>')
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


@info_bp.route('/profile/<user>')
def profile(user):
    party = Party.query.filter_by(name=current_user.name, target=user).first()
    return render_template('profile.html', name=user,
                           id=party.id, public_key=party.publicID)


# Not found Error 404
@info_bp.errorhandler(404)
def page_not_found(error):
    return render_template('not_found.html')


@info_bp.route('/info')
def info():
    return render_template('info.html',
                           parameters={"eA": eA, "eB": eB, "p": p,
                                       "PA": PA, "PB": PB, "QA": QA,
                                       "QB": QB, "A": A})


# Delete everything
@info_bp.route('/delete_all')
def delete_all():
    db.drop_all()
    db.create_all()
    requests.get(server_address + "delete_all")
    return "Done", 200


@info_bp.route('/info_database')
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
