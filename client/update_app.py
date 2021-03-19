import ast
import pickle
import os
import numpy as np
from datetime import datetime
from flask_login import current_user
from pynode import compute_leaf_keys, fill_nodes, create_tree
from pynode import get_node, add_node, lowest_common_node, remove_node
from db_func import get_public_keys, generate_otk, check_mail, check_intels
from db_func import check_group, add_db, update_stage_key
from cryptom import get_key_aes, decrypt_aes
from classes import Message
from mysike import convert_Complex


# Manage the group creation, its modification and
# adding / removing a member
def process_intel(data):

    print('\ndata = ', data)

    groupname = data['groupname']
    dico = ast.literal_eval(data['content'])

    if data['type'] == 'creation':

        members = dico['members'].split(',')

        # Create a non-filled tree
        tree = create_tree(members)

        anode = get_node(tree, current_user.name)
        compute_leaf_keys(anode, current_user.name,
                          data['sender'], dico['infoOTK'], position='receiver')

        public_keys = ast.literal_eval(dico['publicKeys'])
        for key in public_keys:
            public_keys[key] = convert_Complex(public_keys[key])
        path = get_node(tree, current_user.name).path
        fill_nodes(tree, path, public_keys=public_keys)

        if os.path.exists(groupname+'.pkl'):
            os.remove(groupname+'.pkl')

        with open('Tree_'+groupname+"_"+current_user.name+'.pkl',
                  'wb') as output:
            pickle.dump(tree, output, pickle.HIGHEST_PROTOCOL)

        print("Group created")
        tree.info()

    # Here, we assemble the three cases together, since they are similar :
    # 1. We fetch the tree
    # 2. On apply the modification, if any(add / remove in particular)
    # 3. We update the nodes' keys
    # 4. We save the tree in the file
    else:
        print("(Update : ) Ouvertue de l'arbre " +
              'Tree_'+groupname+"_"+current_user.name+'.pkl')
        with open('Tree_'+groupname+"_"+current_user.name+'.pkl',
                  'rb') as input_tree:
            tree = pickle.load(input_tree)

        update_stage_key(tree, data['groupname'])

        if data['type'] == "update_key":

            val = lowest_common_node(current_user.name, data['sender'], tree)
            public_keys = {val: dico[val]}
            for key in public_keys:
                public_keys[key] = convert_Complex(public_keys[key])

            print("Key updated")

        elif data['type'] == "add_member":
            add_node(tree, dico['newmember'])
            val = lowest_common_node(current_user.name,
                                     dico['newmember'], tree)
            public_keys = {val: dico['publicKeys'][val]}
            for key in public_keys:
                public_keys[key] = convert_Complex(public_keys[key])

        elif data['type'] == "remove_member":

            remove_node(tree, dico['member'])
            public_keys = {}

        path = get_node(tree, current_user.name).path
        fill_nodes(tree, path, public_keys=public_keys)
        with open('Tree_'+groupname+"_"+current_user.name+'.pkl',
                  'wb') as output:
            pickle.dump(tree, output, pickle.HIGHEST_PROTOCOL)

        print("Key / tree updated")

    return "Parfait !", 200


# def verification(tree, central_tree, creator, me):
#     central_leaf = get_node(central_tree, current_user.name)
#     leaf = get_node(tree, current_user.name)

#     if central_leaf.public_key != leaf.public_key:
#         raise Exception(
#             "Shared secret computed with X3DH ({} - {}) \
#                 not corresponding !".format(creator, me))
#     else:
#         print("\nChouette ! {} et {} ont les mêmes \
#               Shared Secret !".format(creator, me))

#     if central_tree.public_key != tree.public_key:
#         raise Exception(
#             "Root secret computed ({} - {}) \
#                 not corresponding !".format(creator, me))
#     else:
#         print('Tu es un champion !')


# def send_tree(tree, name_tree, delete=False):
#     headers = {'x-access-tokens': get_token(current_user.name)}
#     with open(name_tree+'.pkl', 'wb') as output:
#         pickle.dump(tree, output, pickle.HIGHEST_PROTOCOL)

#     # Envoi du fichier
#     with open(name_tree+'.pkl', 'rb') as output:
#         response = requests.post(server_address + "/tree/"+name_tree,
#                                  files={"file": output}, headers=headers)
#     if response.status_code != 200:
#         raise Exception(
#             "Le fichier n'a pas été réceptionné par le serveur")

#     if delete:
#         if os.path.exists(name_tree+".pkl"):
#             os.remove(name_tree+".pkl")


# Get all the datas on the server, for the current user
def check_db():
    get_public_keys(current_user.name)
    generate_otk(current_user.name)     # Add the public keys, if necessary
    check_group()                       # Check if new group exist
    intels = check_intels()
    mails = check_mail()

    all_data = mails + intels           # Mix the infos

    if len(all_data) == 0:
        return
    # Important to have the correct order
    # (key update + message != message + key update)
    order_time = np.array([datas['time'] for datas in all_data]).argsort()

    for i in order_time:
        if all_data[i] in mails:     # If it is a message
            mail = all_data[i]

            # Compute the key, according to if it is a P2P message
            # or a group one
            keyy = get_key_aes(
                mail['sender'], mail['recipient'], info_otk=mail['infoOTK'])

            cipher = decrypt_aes(mail['content'], str(keyy))
            mail['content'] = cipher

            heure = datetime.strptime(str(mail['time']), "%m/%d/%Y, %H:%M:%S")
            mail['time'] = heure
            del mail['infoOTK']

            new_mail = Message(**mail)
            add_db(new_mail, 'Message')

        elif all_data[i] in intels:
            intel = all_data[i]
            process_intel(intel)
        else:
            raise Exception("Problème : ni un mail, ni un intel")
