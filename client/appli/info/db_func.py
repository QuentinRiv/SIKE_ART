import os
from sqlalchemy.exc import SQLAlchemyError
import requests
import numpy as np
from numpy import random
from flask_login import current_user
import ast
from time import sleep
from flask import redirect, url_for

from .x25519 import base_point_mult
from .classes import db, User, Party, Group, OneTimeKey, Message
from .mysike import SIKE_compute_pk, eA, eB, server_address


# Return 2 lists : one with the users' name,
# the other with the groups name
def names_n_group(user):
    parties = Party.query.filter_by(name=user).all()
    names = [party.target for party in parties]
    names = list(dict.fromkeys(names))
    groups = Group.query.all()
    groupnames = [group.groupname for group in groups]
    for groupname in groupnames:
        if user not in get_members(groupname):
            groupnames.remove(groupname)

    return names, groupnames


def get_stagekey(groupname):
    group = Group.query.filter_by(owner=current_user.name,
                                  groupname=groupname).first()
    if not group:
        raise Exception("{} not found in the database".format(groupname))
    return group.prevStageKey


def get_otk(owner, serverID=None, delete=False):
    if serverID:
        otk = OneTimeKey.query.filter_by(owner=owner,
                                         serverID=serverID).first()
    else:
        otk = OneTimeKey.query.filter_by(owner=owner).first()

    if not otk:
        for otk in OneTimeKey.query.all():
            print(otk.id, '-', otk.owner, '-', otk.serverID)
        raise Exception("OneTimeKey of {} not found ({})".format(owner,
                                                                 serverID))
    if delete:
        db.session.delete(otk)
        db.session.commit()
    return otk


def add_db(element, kind):
    db.session.add(element)
    try:
        db.session.commit()
        print("{} : {} added to the database".format(element.id, kind))
    except SQLAlchemyError as err:
        print('e = ', err)
        error = str(err.__dict__['orig'])
        print("Erreur :", error)
        raise Exception("Erreur : {}".format(error))


def register_db(name, public_id, side):
    url4 = server_address + "/addParty"
    party = {"owner": name, "public_id": repr(public_id), 'side': side}
    response = requests.post(url4, json=party)
    if response.status_code != 200:
        raise Exception("Problem to register \
                        the public key of {}".format(name))
    return "OK"


def get_public_keys(user):
    headers = {'x-access-tokens': get_token(user)}
    parties = requests.get(server_address + "/members",
                           headers=headers).json()['data']

    for party in parties:
        elems = Party.query.filter_by(
            name=user, target=party["name"], side=party["side"]).all()
        if elems != []:
            continue
            print("Key Bundle", user, "-", party["name"], "déjà existant")
            for elem in elems:
                db.session.delete(elem)
                db.session.commit()

        new_party = Party(name=user,
                          target=party["name"],
                          publicID=party["publicID"],
                          side=party["side"],
                          user_id=party["user_id"]
                          )
        add_db(new_party, "Party {} -> {}".format(user, party["name"]))


def get_mail_db(user, partner):

    sender = user
    recipient = partner

    names, groupnames = names_n_group(user)

    all_messages = []

    if partner in groupnames:   # If it's a group
        # Need to check that the user is in this group
        members = get_members(recipient)
        if sender in members:
            all_messages = Message.query.filter_by(owner=user,
                                                   recipient=recipient).all()

    elif partner in names:
        messagesTo = Message.query.filter_by(owner=user,
                                             sender=sender,
                                             recipient=recipient).all()
        messagesFrom = Message.query.filter_by(owner=user,
                                               sender=recipient,
                                               recipient=sender).all()
        all_messages = np.array(messagesTo + messagesFrom)
    all_messages = np.array(all_messages)

    sorted_messages = np.array([mess.time
                                for mess in all_messages]).argsort()

    if len(all_messages) > 0:
        sorted_messages = all_messages[sorted_messages]
        return sorted_messages
    else:
        return []


def get_id(name, string=False):
    names, groupnames = names_n_group(current_user.name)
    if name in names:
        partner = Party.query.filter_by(target=name).first()
        sentence = "user_"
    else:
        partner = Group.query.filter_by(owner=current_user.name,
                                        groupname=name).first()
        sentence = "group_"
    if not partner:
        raise Exception("Can't get the id of {}".format(name))

    if string:
        return sentence + str(partner.id)
    return partner.id


def get_groupid(groupname):
    group = Group.query.filter_by(owner=current_user.name,
                                  groupname=groupname).first()
    if not group:
        raise Exception("Group {} not found".format(groupname))
    return group.id


def get_last_messages(user):
    names, groupnames = names_n_group(user)
    mails = {}
    for partner in names + groupnames:
        mail = get_mail_db(user, partner)
        if len(mail) != 0:
            mails[partner] = mail[-1]
        elif partner in groupnames:
            mails[partner] = []
    return mails


# Check which group are already existing
def check_group():
    headers = {'x-access-tokens': get_token(current_user.name)}
    groups = requests.get(server_address + "/infogroup",
                          headers=headers).json()['groups']
    for group in groups:
        old_group = Group.query.filter_by(owner=current_user.name,
                                          groupname=group['groupname']).all()
        if len(old_group) != 0:
            continue
        group['owner'] = current_user.name
        new_group = Group(**group)
        add_db(new_group, "Group {}".format(new_group.groupname))
    return


def get_priv_id(name):
    user = User.query.filter_by(name=name).first()
    if not user:
        raise Exception("User {} not found in the database".format(name))
    return user.privID


def get_members(groupname):
    group = Group.query.filter_by(owner=current_user.name,
                                  groupname=groupname).first()
    if not group:
        raise Exception("Group named {} not found".format(groupname))
    return group.members.split(',')


# Compute OTK key pairs, private and public
def generate_otk(name, method="sike27", teste=False):
    if teste:
        i = 0
    else:
        otks = OneTimeKey.query.filter_by(owner=name).all()
        i = len(otks)
    j = 1

    response = requests.get(server_address + "/onetimekey")
    if response.text == '':
        raise Exception('Bizarre bizarre !')
    last_index = int(response.text)
    all_otks = []
    while i < 100:
        if method == "sike27":
            private_key = random.randint(1, min(2**eA, 3**eB))
            public_key = SIKE_compute_pk(private_key, "receiver")
        elif method == "ecdh":
            private_key = os.urandom(32)
            public_key = base_point_mult(private_key)
        elif method == "SIKE751":
            private_key = os.urandom(32)
            public_key = base_point_mult(private_key)
            sleep(0.00487)

        otk = {'owner': name, 'public_otk': repr(public_key)}
        all_otks += [otk]
        new_otk = OneTimeKey(owner=name, privateOTK=private_key,
                             serverID=last_index+j)
        add_db(new_otk, 'OTK')

        i += 1
        j += 1
    if method == "SIKE751":
        sleep(0.00487)
    response = requests.post(server_address + "/onetimekey",
                             json={'keys': all_otks})

    return "Done"


# Return all the intels into the server, for the current user
def check_intels():
    headers = {'x-access-tokens': get_token(current_user.name)}
    intels = requests.get(server_address + "/intels/" +
                          current_user.name, headers=headers).json()['intels']
    return intels


# Return all the messages into the server, for the current user
def check_mail():
    headers = {'x-access-tokens': get_token(current_user.name)}
    mails = requests.get(
        server_address + "/checkmail/" + current_user.name, headers=headers)
    mails = ast.literal_eval(mails.text)['mails']
    return mails


def get_token(username):
    user = User.query.filter_by(name=username).first()
    if not user:
        raise Exception("{} not found in the database".format(username))
    return user.token


def post(address, json={}, homepage=server_address, token_owner=None):
    if not token_owner:
        token_owner = current_user.name
    headers = {'x-access-tokens': get_token(token_owner)}
    response = requests.post(homepage + address,
                             json=json, headers=headers)
    if response.status_code == 401:
        return redirect(url_for('login'))
    else:
        return 0


def get(address, json={}, homepage='http://127.0.0.1:5000', token_owner=None):
    if not token_owner:
        token_owner = current_user.name
    headers = {'x-access-tokens': get_token(token_owner)}
    response = requests.get(homepage + address, headers=headers)
    if response.status_code == 401:
        return 0
    else:
        return response.json()


def update_stage_key(tree, groupname):
    previous_stage_key = tree.private_key
    group = Group.query.filter_by(owner=current_user.name,
                                  groupname=groupname).first()
    if not group:
        raise Exception("Group {} not existing".format(groupname))
    group.prevStageKey = previous_stage_key
    db.session.commit()
    print("Stage key de {} updaté : {}".format(
        current_user.name, group.prevStageKey))
    return


def get_group(groupname):
    group = Group.query.filter_by(owner=current_user.name,
                                  groupname=groupname).first()
    if not group:
        raise Exception("Group '{}' not found".format(groupname))
    return group


def deleteall():
    users = User.query.all()
    parties = Party.query.all()
    messages = Message.query.all()
    groups = Group.query.all()
    otks = OneTimeKey.query.all()
    for element in parties+messages+groups+otks+users:
        db.session.delete(element)
    db.session.commit()
    return "Done", 200
