from werkzeug.utils import secure_filename
from functools import wraps
import requests
from copy import deepcopy
import json

from flask import render_template, request, redirect
from flask import url_for, Blueprint

from flask_login import login_required, current_user

from appli.info.mysike import SIKE_compute_pk, server_address

from appli import db
from .pynode import create_tree, fill_nodes_creator, clear_leaves
from .pynode import get_all_value, get_all_index, read_tree
from .pynode import get_pk_path, get_node, fill_nodes, add_node, write_tree
from .pynode import get_all_pk, get_value_leaves, compute_leaf_keys
from appli.info.db_func import get_members, get_otk, get_token, post
from appli.info.db_func import get_id, names_n_group
from appli.info.db_func import update_stage_key, get_group
from appli.info.update_app import check_db


tree_bp = Blueprint('tree_bp', __name__,
                    template_folder='templates',
                    static_folder='static',
                    static_url_path='/appli/tree/static')


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


@tree_bp.route('/create_group', methods=['POST'])
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
    info_otk = fill_nodes_creator(current_user.name, central_tree)   # Clef

    publicKeys = get_all_pk(central_tree)   # Get the PK

    # Remove the private keys (not obliged, but advised, if party not trusted)
    clear_leaves(central_tree, get_all_value(central_tree))

    # Indicate to the server that a group was created
    # It takes care about the intels
    intel = {'sender': current_user.name,
             'groupname': groupname,
             'members': members,
             'infos': repr(info_otk),
             'publicKeys': repr(publicKeys)}

    post('/create_group', json=intel)

    return "Génial", 200


# Show the tree structure (nodes and vertices)
@tree_bp.route('/show_tree/<groupname>')
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


# Update the key of a leaf
@tree_bp.route('/update_key', methods=['POST'])
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


# Manage the settings page for a group
# (add, delete a member or update a key)
@tree_bp.route('/settings/<partner>')
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


# Add a given member in a given tree
@tree_bp.route('/add_member', methods=['POST'])
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
    dico = {'info_otk': {'creatorOTK': SIKE_compute_pk(private_otk.privateOTK,
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

    # Add the new member to the list of members
    group = get_group(groupname)
    group.members = group.members + "," + new_member
    db.session.commit()

    return "Done", 200


@tree_bp.route('/remove_member', methods=['POST'])
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


@tree_bp.route('/new_group')
@still_connected
def new_group():
    names, groupnames = names_n_group(current_user.name)
    names_id = {name: 'user_'+str(get_id(name)) for name in names}
    return render_template('new_group.html', names=names,
                           groupnames=groupnames, names_id=names_id)
