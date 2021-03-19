from werkzeug.utils import secure_filename
from functools import wraps
import requests
from numpy import random
from copy import deepcopy
from datetime import datetime
import os
import json
from time import time
from x25519 import base_point_mult
from numpy import mean, var

from flask import Flask, render_template, url_for, request, redirect
from flask import flash, send_from_directory, jsonify
from flask_cors import CORS
from flask_login import LoginManager, login_required
from flask_login import current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from mysike import eA, eB, p, A, PA, PB, QA, QB
from mysike import SIKE_compute_pk, compute_pk, server_address

from classes import db, User, Message, Group, Party, OneTimeKey
from pynode import create_tree, fill_nodes_creator, clear_leaves
from pynode import get_all_value, get_all_index, remove_node, read_tree
from pynode import get_pk_path, get_node, fill_nodes, kdf, add_node, write_tree
from pynode import get_all_pk, get_value_leaves, compute_leaf_keys
from db_func import register_db,  generate_otk, add_db, get_mail_db
from db_func import get_public_keys, get_members, get_otk, get_token, post
from db_func import get_id, names_n_group, get_last_messages
from db_func import update_stage_key, get_group
from cryptom import encrypt_aes, get_key_aes, P2Psecret, X3DH
from update_app import check_db


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///client.db'
app.config["SECRET_KEY"] = "_zb_&fMay8K,fg"
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['TOKEN'] = ''


cors = CORS(app, supports_credentials=True)

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'     # Page name to log in
login_manager.login_message = u"Sorry ! You cannot access to this page..."
login_manager.init_app(app)


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


@app.before_first_request
def before_first_request():
    if not os.path.isfile('./client.db'):
        db.create_all()
        for name in ["Quentin", "Bob", "Charlie", "Dom", "Eve"]:
            fill_db(name)


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
        # return ""
    return decorator


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table,
    # use it in the query for the user
    return User.query.get(int(user_id))


# Template for the login
@app.route('/login')
def login():
    return render_template('login.html')


# Login page
@app.route('/login', methods=['POST'])
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
        return redirect(url_for('login'))

    # if the above check passes, then we know
    # the user has the right credentials
    login_user(user, remember=remember)
    r = requests.post(server_address + '/login', auth=(email, password))
    user.token = r.json()['token']
    db.session.commit()
    return redirect(url_for('messenger'))


# When loging out, redirect to the index page
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('start'))


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
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
        return redirect(url_for('signup'))

    fill_db(username, email, password)

    return redirect(url_for('login'))


# Starting page
@app.route('/')
def start():
    return render_template('index.html')


# Return the thesis PDF
@app.route('/paper')
def paper():
    return send_from_directory('static', 'paper.pdf')


# Return the messages of 'partner'
@app.route('/getmessages/<partner>')
@login_required
@still_connected
def get_messages(partner):

    check_db()
    all_messages = get_mail_db(current_user.name, partner)

    message_js = []

    groupnames = names_n_group(current_user.name)[1]
    members = []
    partner_id = ""
    if partner in groupnames:
        members = get_members(partner)

    partner_id = get_id(partner)

    for mess in all_messages:

        direction = "sent" if mess.sender == current_user.name else "received"

        sender_id = get_id(mess.sender)
        message = {"sender": "user_" + str(sender_id),
                   "recipient": mess.recipient,
                   "content": mess.content,
                   "time": mess.time.time().strftime("%H:%M:%S"),
                   "direction": direction,
                   "imgURL": url_for('static',
                                     filename='/imag/' + mess.sender + '.PNG')}
        message_js += [message]

    return {'messages': message_js, 'members': members, 'id': partner_id}


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


@app.route('/create_group', methods=['POST'])
@login_required
@still_connected
def create_group():
    # We takes the data of the HTML page
    data = request.json

    # Get the info about the group (and secure the name of the group)
    # e.g. : 'tree one' becomes 'tree_one'
    groupname, members = secure_filename(data['name']), data['members']

    data['creator'] = current_user.name

    # Add the creator to the group if he forgot to be in it
    if current_user.name not in members:
        members += [current_user.name]

    # Creation of the tree, not filled
    central_tree = create_tree(members)
    infoOTK = fill_nodes_creator(current_user.name, central_tree)   # Clef

    publicKeys = get_all_pk(central_tree)   # Get the PK

    # Remove the private keys (not obliged, but advised, if party not trusted)
    clear_leaves(central_tree, get_all_value(central_tree))

    # Indicate to the server that a group was created
    # It takes care about the intels
    intel = {'sender': current_user.name,
             'groupname': groupname,
             'members': members,
             'infos': repr(infoOTK),
             'publicKeys': repr(publicKeys)}

    post('/creategroup', json=intel)

    return "Génial", 200


# Show the tree structure (nodes and vertices)
@app.route('/show_tree/<groupname>')
@still_connected
@login_required
def show_tree(groupname):
    tree = read_tree(groupname)
    all_index = get_all_index(tree)

    nodes = []
    for index in all_index:
        anode = get_node(tree, index)
        unode = {"value": anode.value, "name": 'node'}

        if anode.parent:
            unode["parent"] = anode.parent.value
        if anode.isLeaf:
            unode['name'] = 'user_' + str(get_id(anode.value))
        if anode.private_key:
            unode["secretK"] = anode.private_key
        else:
            unode["secretK"] = ""
        nodes += [unode]
    data = {'info': nodes}
    return render_template('show_tree.html', data=data)


@app.route('/profile/<user>')
@still_connected
def profile(user):
    party = Party.query.filter_by(name=current_user.name, target=user).first()
    return render_template('profile.html', name=user,
                           id=party.id, public_key=party.publicID)


@app.route('/sendmessage', methods=["POST"])
@still_connected
def sendmessage():
    data = request.json     # Get the data (sender, recipient, message)
    check_db()
    names, groupnames = names_n_group(current_user.name)
    sender, recipient = data['sender'], secure_filename(data['recipient'])
    data['destination'] = recipient

    # We make a copy for ourself
    new_message = Message(owner=sender,
                          sender=sender,
                          content=data['content'],
                          time=datetime.now(),
                          recipient=recipient)
    add_db(new_message, 'Message')

    if recipient in groupnames:
        key = get_key_aes(sender, recipient)
    elif recipient in names:
        key, dico = P2Psecret(sender, recipient, 'sender')
        data['infoOTK'] = repr(dico)
    else:
        raise Exception("Problem : the recipient name : {}".format(recipient))

    print('Send message : ', key)

    encrypted_data = encrypt_aes(data['content'], str(key))
    data['content'] = repr(encrypted_data)
    print('encrypted_data :', encrypted_data)

    headers = {'x-access-tokens': get_token(current_user.name)}
    requests.post(server_address + "/mailbox", json=data, headers=headers)

    return jsonify(answer="Génial")


@app.route('/update_key', methods=['POST'])
@still_connected
@login_required
def update_key():
    data = request.json
    print('data = ', data)
    groupname = data["groupname"]
    if groupname not in names_n_group(current_user.name)[1]:
        return "Rien à faire ici", 200

    # Updating of the tree
    tree = read_tree(groupname)
    update_stage_key(tree, data['groupname'])

    usernode = get_node(tree, data['user'])
    usernode.update_secret_key(data['secretK'])

    path = usernode.path
    fill_nodes(tree, path)

    write_tree(groupname, tree)

    members = get_members(groupname)
    # We don't send to the member who modified, since
    # they already did it the modifications for themself
    members.remove(current_user.name)
    dico = get_pk_path(tree, usernode)
    headers = {'x-access-tokens': get_token(current_user.name)}
    for member in members:
        intel = {'sender': current_user.name,
                 'content': repr(dico),
                 'recipient': member,
                 'type': 'update_key',
                 'groupname': groupname}
        requests.post(server_address + "/intels/" + member,
                      json=intel, headers=headers)

    print('\nSuccess : key updated')
    return "Tout de bon", 200


@app.route('/settings/<partner>')
@still_connected
@login_required
def settings(partner):
    members_id, not_members_id = {}, {}
    names, groupnames = names_n_group(current_user.name)
    check_db()
    if partner in groupnames:
        members = get_members(partner)
        not_members = [name for name in names if name not in members]
        for not_member in not_members:
            not_members_id[not_member] = get_id(not_member, string=True)
        for member in members:
            members_id[member] = get_id(member, string=True)
    return render_template('settings.html', partner=partner,
                           notmembersid=not_members_id,
                           members=members, notmembers=not_members,
                           membersid=members_id)


@app.route('/add_member', methods=['POST'])
@still_connected
@login_required
def add_member():
    check_db()

    data = request.json
    groupname, new_member = data['groupname'], data['newmember']

    # Get the tree, add a node and get the node
    tree = read_tree(groupname)
    add_node(tree, new_member)
    newnode = get_node(tree, new_member)

    # We take a random OTK private key, with the corresponding index
    private_otk = get_otk(current_user.name)
    ind_private_otk = private_otk.serverID

    # Creation of the shared key (leaf key) and we put it in the leaf attribute
    headers = {'x-access-tokens': get_token(current_user.name)}
    public_otk = requests.get(server_address + "/getOTK/" +
                              new_member + "/" + str(-1),
                              headers=headers).json()
    otkeys = {'privateOTK': str(ind_private_otk),
              'publicOTK': public_otk['publOTK']}
    compute_leaf_keys(newnode, current_user.name,
                      newnode.value, otkeys, 'initiator')

    # Update the key pairs
    fill_nodes(tree, newnode.path)

    members = get_members(groupname)
    pks = get_pk_path(tree, newnode)
    publicKeys = get_all_pk(tree)

    dico = {'groupname': groupname,
            'publicKeys': pks,
            'newmember': new_member}

    # Intels for the already existing members
    headers = {'x-access-tokens': get_token(current_user.name)}
    for member in members:
        intel = {'sender': current_user.name,
                 'content': repr(dico),
                 'recipient': member,
                 'type': data['type'],
                 'groupname': groupname}
        requests.post(server_address + "/intels/" + member,
                      json=intel, headers=headers)

    # We make a copy not to erase our tree
    central_tree = deepcopy(tree)
    clear_leaves(central_tree, get_all_value(central_tree))

    # Intel for the new member only,
    # so that they create its tree
    dico = {'infoOTK': {'creatorOTK': SIKE_compute_pk(private_otk.privateOTK,
                        'initiator'),
                        'partnerOTK': public_otk['indexOTK']},
            'groupname': groupname,
            'members': ','.join(get_value_leaves(tree)),
            'publicKeys': repr(publicKeys)}
    intel = {'sender': current_user.name,
             'content': repr(dico),
             'recipient': new_member,
             'type': 'creation',
             'groupname': groupname}

    headers = {'x-access-tokens': get_token(current_user.name)}
    requests.post(server_address + "/intels/"+new_member,
                  json=intel, headers=headers)
    group = get_group(groupname)
    group.members = group.members + "," + new_member
    db.session.commit()

    return "Done", 200


@app.route('/remove_member', methods=['POST'])
@still_connected
@login_required
def remove_member():
    # It is important to be up to date before removing a member
    # in order to be sure we get the correct keys
    check_db()

    data = request.json

    # Intels for the already existing members, so that they
    # get the tree into the server, and adapt theirs
    groupname = data['groupname']
    members = get_members(groupname)
    headers = {'x-access-tokens': get_token(current_user.name)}

    group = get_group(groupname)

    for member in members:
        dico = {'groupname': groupname,
                'member': data['member']}

        intel = {'sender': current_user.name,
                 'content': json.dumps(dico),
                 'recipient': member,
                 'type': 'remove_member',
                 'groupname': groupname}

        requests.post(server_address + "/intels/" +
                      member, json=intel, headers=headers)

    members = get_members(groupname)
    if data['member'] in members:
        members.remove(data['member'])
        group.members = ','.join(members)
        db.session.commit()

    return "User removed !", 200


@app.errorhandler(404)
def page_not_found(error):
    return render_template('not_found.html')


@app.route('/messenger')
@still_connected
@login_required
def messenger():
    check_db()
    groupnames = names_n_group(current_user.name)[1]
    lastmails = get_last_messages(current_user.name)
    print('lastmails = ', lastmails)
    my_id = 'user_' + str(get_id(current_user.name))
    message_js = []
    for partner in lastmails:
        mail = lastmails[partner]

        if partner in groupnames:
            partner_id = 'group_' + str(get_id(partner))
        else:
            partner_id = 'user_' + str(get_id(partner))

        direction = "sent" if mail.sender == current_user.name else "received"

        message = {"sender": mail.sender,
                   "recipient": mail.recipient,
                   "content": mail.content,
                   "time": mail.time.time().strftime("%H:%M:%S"),
                   "direction": direction,
                   "imgURL": url_for('static',
                                     filename='imag/' + partner_id + '.PNG'),
                   "partner": partner}

        if partner in groupnames:
            partner_id = "group_" + get_id(partner)
        else:
            partner_id = "user_" + get_id(partner)

            message["imgURL"] = url_for('static',
                                        filename='imag/' + partner_id + '.png')
        message_js += [message]

    return render_template('messenger.html', lastmails=message_js,
                           current=my_id, groupnames=groupnames)


@app.route('/new_conversation')
@login_required
@still_connected
def new_conversation():

    check_db()
    lastmails = get_last_messages(current_user.name)
    partners = list(lastmails.keys())
    names, groupnames = names_n_group(current_user.name)

    other_partners = [name for name in names if name not in partners]
    partners_id = [Party.query.filter_by(target=partner)
                              .first().user_id for partner in other_partners]
    others = dict(zip(partners_id, other_partners))
    return render_template('new_conversation.html',
                           others=others, partners_id=partners_id)


@app.route('/new_group')
@still_connected
@still_connected
def new_group():
    names, groupnames = names_n_group(current_user.name)
    names_id = {name: 'user_'+str(get_id(name)) for name in names}
    return render_template('new_group.html', names=names,
                           groupnames=groupnames, names_id=names_id)


@app.route('/info')
def info():
    return render_template('info.html', parameters={"eA": eA, "eB": eB, "p": p,
                           "PA": PA, "PB": PB, "QA": QA, "QB": QB, "A": A})


@app.route('/faisability', methods=['GET', 'POST'])
def faisability():
    if request.method == 'GET':
        return render_template('faisability.html')
    else:
        headers = {'x-access-tokens': get_token(current_user.name)}
        data = request.json         # On récupère les données de la page HTML
        print('data = ', data)
        mode = data['mode']
        method = data['method']
        if mode == 'create_group':
            for user in User.query.all():
                db.session.delete(user)
                db.session.commit()
            create_time = []
            add_time = []
            remove_time = []
            update_time = []
            members = ["Quentin", "Alice", "Bob", "Charlie", "Dom",
                       "Eve", "Fab",  "George", "Harry", "Ive", "Jean"]
            for mem in members+["Kyle"]:
                generate_otk(mem, method=method, teste=True)
                if method == "sike27":
                    private_key = random.randint(1, min(2**eA, 3**eB))
                    public_key = SIKE_compute_pk(private_key, "receiver")
                    register_db(mem, public_key, 'receiver')
                    new_user = User(email=mem+".rivollat@etu.unige.ch",
                                    name=mem,
                                    password=generate_password_hash(
                                        "123", method='sha256'),
                                    privID=private_key)

                # add the new user to the database
                elif method == "ecdh" or method == "SIKE751":
                    private_key = os.urandom(32)
                    public_key = base_point_mult(private_key)
                    register_db(mem, public_key, 'receiver')
                    new_user = User(email=mem+".rivollat@etu.unige.ch",
                                    name=mem,
                                    password=generate_password_hash(
                                        "123", method='sha256'),
                                    privID=private_key)
                add_db(new_user, 'User {}'.format("Quentin"))
            get_public_keys("Quentin")
            for i in range(25):
                print('i = ', i)
                generate_otk("Quentin")

                groupname = "group_" + str(random.randint(1000))

                t0 = time()
                # Création de l'arbre, non rempli
                central_tree = create_tree(members)
                public_keys = fill_nodes_creator("Quentin", central_tree,
                                                 method=method)

                # Indique au serveur qu'un groupe a été créé.
                # Il se chargera de faire les intels
                data2 = {'sender': "Quentin", 'groupname': groupname,
                         'members': members, 'publicK': repr(public_keys)}
                headers = {'x-access-tokens': get_token(current_user.name)}
                requests.post(server_address + "/creategroup",
                              json=data2, headers=headers)

                t1 = time()
                create_time += [t1-t0]

                #############################################################

                generate_otk("Quentin", method=method)

                data = request.json

                new_member = "Kyle"

                # On prend une clef OTK privée, au hasard
                private_otk = get_otk("Quentin")
                ind_private_otk = private_otk.serverID

                # Création du shared secret = leaf key
                headers = {'x-access-tokens': get_token(current_user.name)}
                public_otk = requests.get(server_address + "/getOTK/" +
                                          new_member+"/"+str(-1),
                                          headers=headers).json()
                otkeys = {'privateOTK': str(ind_private_otk),
                          'publicOTK': public_otk['publOTK']}
                [a, b, c] = X3DH("Quentin", new_member,
                                 'initiator', OTKeys=otkeys, method=method)
                leaf_secretk = kdf(a, b, c, p, method=method)

                tree = deepcopy(central_tree)
                add_node(tree, new_member,
                         secret_key=leaf_secretk, method=method)

                newnode = get_node(tree, new_member)

                fill_nodes(tree, newnode.path, method=method)

                pks = get_pk_path(tree, newnode)
                dico = {'groupname': groupname,
                        'newmember': new_member,
                        'publicKeys': pks}

                # Intels à destination des anciens membres
                # (y compris celui qui a rajouté le nouveau membre)
                headers = {'x-access-tokens': get_token(current_user.name)}
                for member in members:
                    intel = {'sender': "Quentin",
                             'content': repr(dico),
                             'recipient': member,
                             'type': 'new_group',
                             'groupname': groupname}
                    requests.post(server_address + "/intels/" + member,
                                  json=intel, headers=headers)

                # Intel à destination du nouveau membre,
                # pour qu'il crée l'arbre de son côté
                dico = {'infoOTK': {'creatorOTK':
                                    compute_pk(private_otk.privateOTK,
                                               side='initiator',
                                               method=method),
                                    'partnerOTK': public_otk['indexOTK']},
                        'groupname': groupname,
                        'newmember': new_member}
                intel = {'sender': "Quentin",
                         'content': repr(dico),
                         'recipient': new_member,
                         'type': 'creation',
                         'groupname': groupname}

                requests.post(server_address + "/intels/" +
                              new_member, json=intel, headers=headers)

                t2 = time()

                add_time += [t2-t1]

                remove_member = "Bob"
                remove_node(tree, remove_member)

                path = get_node(tree, "Quentin").path
                fill_nodes(tree, path, public_keys={}, method=method)

                for member in members:
                    dico = {'groupname': groupname,
                            'member': remove_member}

                    intel = {'sender': "Quentin",
                             'content': json.dumps(dico),
                             'recipient': member,
                             'type': 'remove_member'}

                    requests.post(server_address + "/intels/" +
                                  member, json=intel, headers=headers)

                t3 = time()
                remove_time += [t3-t2]

                ##################################################

                updated_member = "Charlie"
                usernode = get_node(tree, updated_member)
                usernode.update_secret_key(random.randint(1000))

                path = usernode.path
                fill_nodes(tree, path, method=method)

                # On n'envoie pas à celui qui a modifié, puisqu'il a déjà
                # fait les changements de son côté
                dico = get_pk_path(tree, usernode)
                for member in members:
                    intel = {'sender': current_user.name,
                             'content': repr(dico),
                             'recipient': member,
                             'type': 'update_key',
                             'groupname': groupname}
                    requests.post(server_address + "/intels/" + member,
                                  json=intel, headers=headers)

                t4 = time()
                update_time += [t4-t3]

            print('Time :', create_time)
            print('\nCreate group :')
            print('Mean :', mean(create_time))
            print('Variance :', var(create_time))

            print('Time :', add_time)
            print('\nAdd :')
            print('Mean :', mean(add_time))
            print('Variance :', var(add_time))

            print('Time :', remove_time)
            print('\nRemove :')
            print('Mean :', mean(remove_time))
            print('Variance :', var(remove_time))

            print('Time :', update_time)
            print('\nUpdate :')
            print('Mean :', mean(update_time))
            print('Variance :', var(update_time))

        elif mode == 'send_message':

            print('mode = ', mode)
            get_public_keys("Quentin")

            send_time = []
            sender, recipient = "Quentin", "Bob"

            members = ["Quentin", "Alice", "Bob", "Charlie", "Dom",
                       "Eve", "Fab",  "George", "Harry", "Ive", "Jean"]
            for mem in members:
                generate_otk(mem, method=method)

            # print('\n----')

            for j in range(50):
                print('i = ', j)

                t0 = time()
                message = "a random message " + str(random.randint(1000))

                # On fait une copie pour soi :
                new_message = Message(owner=sender,
                                      sender=sender,
                                      content=message,
                                      time=datetime.now(),
                                      recipient=recipient)
                add_db(new_message, 'Message')

                key, dico = P2Psecret(sender, recipient,
                                      'sender', method=data['method'])

                # print('\nYo')

                ciphertext = encrypt_aes(message, str(key))
                data2 = {'content': ciphertext,
                         'sender': sender,
                         'recipient': recipient,
                         'infoOTK': repr(dico), 'destination': recipient}

                requests.post(server_address + "/mailbox",
                              json=data2, headers=headers)

                t1 = time()
                send_time += [t1-t0]

            print('Time :', send_time)
            print('\nSending message :')
            print('Mean :', mean(send_time))
            print('Variance :', var(send_time))
        # elif mode=='add_member'

        elif mode == "initialisation":
            # Empty the databases
            initialisation_time = []

            for o in range(1):
                users = User.query.all()
                parties = Party.query.all()
                messages = Message.query.all()
                groups = Group.query.all()
                otks = OneTimeKey.query.all()
                for element in users+parties+messages+groups+otks:
                    db.session.delete(element)
                db.session.commit()
                requests.get(server_address + "/deleteall", headers=headers)
                t0 = time()
                requests.get(server_address + "/onetimekey")
                generate_otk("Quentin", method=method, teste=True)
                t1 = time()
                initialisation_time += [t1-t0]

                if method == "sike27":
                    private_key = random.randint(1, min(2**eA, 3**eB))
                    public_key = SIKE_compute_pk(private_key, "receiver")
                    register_db("Quentin", public_key, 'receiver')
                    new_user = User(email="quentin.rivollat@etu.unige.ch",
                                    name="Quentin",
                                    password=generate_password_hash(
                                        "123", method='sha256'),
                                    privID=private_key)

                    # add the new user to the database
                    add_db(new_user, 'User {}'.format("Quentin"))
                elif method == "ecdh" or method == "SIKE751":
                    private_key = os.urandom(32)
                    public_key = base_point_mult(private_key)
                    register_db("Quentin", public_key, 'receiver')
                    new_user = User(email="quentin.rivollat@etu.unige.ch",
                                    name="Quentin",
                                    password=generate_password_hash(
                                        "123", method='sha256'),
                                    privID=private_key)

                    # add the new user to the database
                    add_db(new_user, 'User {}'.format("Quentin"))
            print('Time :', initialisation_time)
            print('\nInitialisation group :')
            print('Mean :', mean(initialisation_time))
            print('Variance :', var(initialisation_time))

        return "Good", 200


if __name__ == '__main__':
    print('Allo ?')
    app.run(debug=True, use_reloader=True, threaded=True, port=8080)
