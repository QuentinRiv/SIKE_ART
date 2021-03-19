from copy import deepcopy
import math
from mysike import eA, eB, p, createSS
from mysike import compute_pk, Complex, server_address
import numpy as np
from flask_login import current_user
import requests
from cryptom import X3DH
from db_func import get_otk, get_priv_id, get_token
import pickle


# Tree's nodes, with their attributes
class Node():
    def __init__(self, value, index=None, children=None,
                 parent=None, path=None, copath=None,
                 secretK=None, publicK=None, isLeaf=False):
        self.value = value          # Its name (member or index)
        # Children (2 if not a leaf, else None)
        self.children = children
        self.parent = parent        # Parent (except for the root)
        # Position in the tree [x, y] => x : depth (start at 0),
        # y : position among the nodes in the same depth x
        self.index = index
        self.path = path            # Path until the root
        self.copath = copath        # Copath until the root
        self.private_key = secretK      # Private key
        self.public_key = publicK      # Public key
        self.isLeaf = isLeaf        # Indicate if it's a leaf of not
        self.side = 'initiator' if (index[1]%2) == 0 else 'receiver'
        # Initiator or receiver

    # Print a kind of tree shape
    def __str__(self, level=0):

        ret = "|\t"*(level) + "+-----" + repr(self.value) + "\n"
        if self.children:
            for child in self.children:
                ret += child.__str__(level+1)
        return ret

    def __repr__(self):
        return '<Node {}>'.format(self.value)

    # Print all the attributes
    def info(self):
        print("\nValue :", self.value)
        if not self.isLeaf:     # For the leaves
            print("Children :",
                  self.children[0].value, "-", self.children[1].value)
        print("Index :", self.index)
        if self.parent:     # For the root
            print("Parent :", self.parent.value)
        print("Path :", self.path)
        print("Copath :", self.copath)
        print("Secret Key :", self.private_key)
        print("Public Key :", self.public_key)
        print("Side :", self.side)

    def compute_leaf_key(self, method="sike27"):
        if self.private_key:
            self.public_key = compute_pk(self.private_key,
                                      side=self.side, method=method)

    def update_secret_key(self, key):
        self.private_key = key
        self.compute_leaf_key()


class Tree():
    def __init__(self, members):
        self.members = members

        root = create_tree(members)
        self.root = root
        self.all_nodes = get_all_nodes(root)
        self.all_leaves = get_all_leaves(root)
        self.num_leaves = len(self.all_leaves)
        self.depth = math.floor(np.log2(self.num_leaves))

    def get_node(self, value):
        for node in self.all_nodes:
            if (node.index == value) or (node.value == value):
                return node

    def __str__(self):
        return str(self.root)

    def insert(self, node):
        add_node(self.tree, node)


# Return the index of all the nodes of the tree
def info_tree(members):
    length = len(members)        # Number of leaves
    n = 2*length - 1             # Number of nodes (including leaves)
    leaves = []
    for i in range(1, n+1):
        x = math.floor(np.log2(i))
        y = i - 2**x
        leaves += [[x, y]]

    return leaves


# Return all the index (not sorted)
def get_all_index(anode):
    if not anode.isLeaf:
        l_index = get_all_index(anode.children[0])
        r_index = get_all_index(anode.children[1])
        return [anode.index] + l_index + r_index
    return [anode.index]


# Return all the values (not sorted)
def get_all_value(anode):
    if not anode.isLeaf:
        lIndex = get_all_value(anode.children[0])
        rIndex = get_all_value(anode.children[1])
        return [anode.value] + lIndex + rIndex
    return [anode.value]


# Return all the values, but just for the leaves
def get_value_leaves(anode):
    if not anode.isLeaf:
        l_value = get_value_leaves(anode.children[0])
        r_value = get_value_leaves(anode.children[1])
        return l_value + r_value
    return [anode.value]


# Create the tree, by first copying the members
def create_tree(members):
    members_copy = deepcopy(members)
    all_index = info_tree(members_copy)
    central_tree = create_node(all_index, members_copy)

    update_path(central_tree)
    update_copath(central_tree)
    return central_tree


# Creation of the nodes, et indicate the children, parent and
# node / leaf.
# The idea is to go the deepest as possible, then create the leaves,
# return them and construct iteratively the parents, up to the root
def create_node(all_index, members, parent=None, index=[0, 0]):
    [x, y] = index
    if index in all_index:
        value = str(index[0])+str(index[1])
        new_node = Node(value, index=index, parent=parent)
        left_node = create_node(all_index, members, new_node, [x+1, 2*y])
        right_node = create_node(all_index, members, new_node, [x+1, 2*y+1])

        # We don't add a child, since being here means
        # it is a leaf
        if (left_node == 0) and (right_node == 0):
            new_node.value = members.pop(0)
            return new_node
        else:
            new_node.children = [left_node, right_node]
            return new_node

    # If the index is not in the list, then the parent
    # was a leaf (we return 0 to indicate this)
    else:
        parent.isLeaf = True
        return 0


def get_all_nodes(tree):
    all_nodes = []
    queue = [tree]
    while queue:
        s = queue.pop(0)
        all_nodes += [s]
        if not s.isLeaf:
            queue += s.children
    return all_nodes


def get_all_leaves(tree):
    all_leaves = []
    queue = [tree]
    while queue:
        s = queue.pop(0)
        if not s.isLeaf:
            queue += s.children
        else:
            all_leaves += [s]
    return all_leaves


# Update the path, iterativaly
# We go to the leaves, along with adding the node in 'path'
def update_path(anode, path=[]):
    if not anode.isLeaf:
        update_path(anode.children[0], path + [anode.index])
        update_path(anode.children[1], path + [anode.index])
    anode.path = path + [anode.index]
    return 0


def update_copath(anode, path=[]):
    if not anode.isLeaf:
        update_copath(anode.children[0], path + [anode.children[1].index])
        update_copath(anode.children[1], path + [anode.children[0].index])
    anode.copath = path
    return 0


# Return the node corresponding to the index or value given
def get_node(node, info, check=False):
    if isinstance(info, list):
        anode = get_node_bis(node, index=info)
    elif isinstance(info, str):
        anode = get_node_bis(node, value=info)

    if anode == 0:
        if check:
            return 0
        else:
            print('\nArbre donné :\n', node)
            raise Exception(
                "The node {} was not found in the tree".format(info))
    return anode


def get_node_bis(node, index=None, value=None):
    # Lorsqu'on tombe sur le bon
    # When we get the good one
    if (index == node.index) or (value == node.value):
        return node
    # If we end up on a leaf, without reaching the correct node,
    # then the sibling is the correct one
    # Thus, we return 0 to indicate it (cf n1 and n2)
    elif node.isLeaf:
        return 0
    else:
        n1 = get_node_bis(node.children[0], index, value)
        n2 = get_node_bis(node.children[1], index, value)
        # We return the other one
        if n1 == 0:
            return n2
        else:
            return n1


# Function to use only by the group creator, and only once
def fill_nodes_creator(user, node, method="sike27"):

    # When the leaves' keys were set, we compute the keys
    # of the parents, based on the children' ones
    if not node.isLeaf:
        l_dico = fill_nodes_creator(user, node.children[0], method)
        r_dico = fill_nodes_creator(user, node.children[1], method)
        # We take the 'initiator' side, because we take the left key
        # (choice with no importance, the inverse is possible, since
        # we know both private keys)

        secret_key = createSS(node.children[1].public_key,
                              node.children[0].private_key,
                              side='initiator', method=method)

        deduce_private_key(node, secret_key, is_node=True, method=method)

        l_dico.update(r_dico)     # We mix together the dicts
        return l_dico

    # We go down until the leaves, then we compute their shared secret SS
    # and the corresponding public key, in order to put them in
    # the attibute of the node
    else:

        private_otk = get_otk(user)
        # Index of the corresponding public key which is on the server
        ind_private_otk = private_otk.serverID
        headers = {'x-access-tokens': get_token(current_user.name)}
        requests.get(server_address + "/lockOTK/"+str(ind_private_otk),
                     headers=headers)

        response = requests.get(server_address + "/getOTK/"
                                + node.value + "/" + str(-1), headers=headers)

        public_otk = response.json()
        OTKeys = {'privateOTK': str(ind_private_otk),
                  'publicOTK': public_otk['publOTK']}

        compute_leaf_keys(node, user, node.value, OTKeys, 'initiator', method)

        # creatorOTK : the corresponding public OTK key of the private one used
        # partner : indicates the public OTK key used from the partner
        # into the server
        dico = {node.value: {'creatorOTK': compute_pk(private_otk.privateOTK,
                             side='initiator', method=method),
                             'partnerOTK': public_otk['indexOTK']}}
        return dico


# Fill the attributes 'secretK' and 'publicK' for each node,
# with the given data
# If publicKs and secretKs are empty, we consider that we have enough
# information about some nodes in order to compute everything
def compute_leaf_keys(anode, user, partner, public_key,
                      position, method='sike27'):
    # We fetch the secret key
    if user == partner:
        leaf_sB = get_priv_id(user)

    else:
        if position == 'initiator':
            OTKeys = public_key

        elif position == 'receiver':
            # The member who computes the shared secret with X3DH
            # use the index of the public key the creator used
            # along with the public key corresponsing to the private
            # one used
            OTKeys = {'privateOTK': str(public_key['partnerOTK']),
                      'publicOTK': repr(public_key['creatorOTK'])}

        [a, b, c] = X3DH(user, partner, position, OTKeys=OTKeys, method=method)
        leaf_sB = kdf(a, b, c, p, method)

    deduce_private_key(anode, leaf_sB)
    print("Pour {}, la clef privée \
            est : {}".format(anode.value, anode.private_key))


def fill_nodes(node, tofill, public_keys={}, method='sike27'):
    # If we know the public key, we put it in the node
    if node.value in public_keys:
        node.public_key = public_keys[node.value]

    # If it's a parent, we first need that the children get their
    # public keys placed
    if not node.isLeaf:
        if node.index in tofill:

            fill_nodes(node.children[0], tofill, public_keys, method)
            fill_nodes(node.children[1], tofill, public_keys, method)

            # print("\nNoeud :", node.value)

            # We look at who gave its private key (in path) and who gave
            # its public one
            if node.children[1].private_key:
                # print("On connait la sK de ",
                #       node.children[1].value, ":", node.children[1].private_key)
                # print("On connait la pK de ",
                #       node.children[0].value, ":", node.children[0].public_key)
                secret_key = createSS(node.children[0].public_key,
                                      node.children[1].private_key,
                                      side='receiver', method=method)

            elif node.children[0].private_key:
                # print("On connait la sK de ",
                #       node.children[0].value, ":", node.children[0].private_key)
                # print("On connait la pK de ",
                #       node.children[1].value, ":", node.children[1].public_key)
                secret_key = createSS(node.children[1].public_key,
                                      node.children[0].private_key,
                                      side='initiator', method=method)

            deduce_private_key(node, secret_key, is_node=True, method=method)
            # print('SecretK de ', node.value, '= ', node.private_key)
            if not node.public_key:
                raise Exception("Problème chez {}".format(node.value))

            # print("Publique de", node.value, ":", node.public_key)


# Deduce the private key (adapt according to the side)
def deduce_private_key(node, secret, is_node=False, method="sike27"):
    if is_node:
        if isinstance(secret, Complex):
            asecret_key = (secret*secret.conj()).re
        else:
            secret = ord(secret[0])
            if secret == 0:
                secret = 1
            asecret_key = secret
    else:
        if method == "ecdh" or method == "SIKE751":
            if secret == 0:
                secret = 1
        asecret_key = secret

    if method == "sike27":
        if node.side == 'initiator':
            asecret_key = asecret_key % (2**eA)
        else:
            asecret_key = asecret_key % (3**eB)

    node.private_key = asecret_key
    node.compute_leaf_key(method)
    if not node.public_key:
        raise Exception("Gros problème chez {} \
            (avait la sK = {})".format(node.value, asecret_key))

    return 0


# Erase the private keys of the nodes indicated in the path
def clear_leaves(anode, path):
    if (anode.value in path) or (anode.index in path):
        anode.private_key = None
    if not anode.isLeaf:
        clear_leaves(anode.children[0], path)
        clear_leaves(anode.children[1], path)


# Add a node, by making the correct modification on the tree structure
def add_node(tree, name, secret_key=None, public_key=None, method="sike27"):
    print("\n\nRajout :")
    n = len(get_value_leaves(tree))
    [x, y] = get_index((n+1)*2-1)        # Index of the node to add
    print("Nouvel index ({}) :".format(n), [x, y])

    # Check that a node is not already there
    if get_node(tree, [x, y], True) != 0:
        bidule = get_node(tree, [x, y])
        bidule.info()
        val = [value_to_index(tree, value) for value in get_value_leaves(tree)]
        ind_correct_parent = get_highest_node(val)
        [gx, gy] = ind_correct_parent
        # Correction :
        x, y = gx+1, 2*gy+1
        print("Position déjà prise. Changer à {}".format([x, y]))

    ind_parent = [x-1, math.ceil((y-1)/2)]    # Compute the index of the parent
    [xx, yy] = ind_parent
    indGParent = [xx-1, math.ceil((yy-1)/2)]

    greatp_node = get_node(tree, indGParent)
    parent_node = get_node(tree, ind_parent)    # Former leaf

    new_parent = Node(value=str(xx)+str(yy),
                      index=ind_parent,
                      parent=greatp_node)

    print("Nom du parent :", parent_node.value)
    print("Et nom du nouveau gars :", name)

    # It is important to keep the side of the former leaf
    # If they were 'initiator', we place it at the left (first children)
    if parent_node.side == 'initiator':
        new_leave1 = Node(value=parent_node.value,
                          index=[xx+1, 2*yy],
                          parent=new_parent,
                          children=[],
                          secretK=parent_node.private_key,
                          publicK=parent_node.public_key,
                          isLeaf=True)

        new_leave2 = Node(value=name,
                          index=[xx+1, 2*yy+1],
                          parent=new_parent,
                          secretK=secret_key,
                          publicK=public_key,
                          children=[],
                          isLeaf=True)

        new_parent.children = [new_leave1, new_leave2]

    else:
        new_leave1 = Node(value=parent_node.value,
                          index=[xx+1, 2*yy+1],
                          parent=new_parent,
                          children=[],
                          secretK=parent_node.private_key,
                          publicK=parent_node.public_key,
                          isLeaf=True)

        new_leave2 = Node(value=name,
                          index=[xx+1, 2*yy],
                          parent=new_parent,
                          secretK=secret_key,
                          publicK=public_key,
                          children=[],
                          isLeaf=True)
        new_parent.children = [new_leave2, new_leave1]

    if (public_key) and (not secret_key):
        deduce_private_key(new_leave2, secret_key,
                           is_node=False, method=method)

    greatp_node.children.remove(parent_node)
    greatp_node.children += [new_parent]

    update_path(tree)
    update_copath(tree)


# We remove a node, and its sibling take the position of the common parent
def remove_node(tree, name):
    node2del = get_node(tree, name)      # Node to delete
    [x, y] = node2del.index

    # Parent node, which will be replaced by the sibling
    parent = get_node(tree, [x-1, math.ceil((y-1)/2)])
    [_, yy] = parent.index

    parent.children.remove(node2del)
    sibling = parent.children[0]

    # If the sibling has to get the keys of its parent before deleting it
    # Otherwise, no need to worry, since it is None by default
    sibling.private_key = parent.private_key
    sibling.public_key = parent.public_key

    Gparent = parent.parent
    Gparent.children.remove(parent)
    if (yy % 2) == 0:
        newGPchildren = [sibling, Gparent.children[0]]
    else:
        newGPchildren = [Gparent.children[0], sibling]
    Gparent.children = newGPchildren

    # Get the parent info
    sibling.parent = Gparent
    sibling.index = parent.index
    sibling.side = parent.side

    # We re-compute the key, in case the side changed
    sibling.compute_leaf_key()
    if not sibling.isLeaf:
        sibling.value = parent.value

    update_path(tree)
    update_copath(tree)


# Compute the index of a new node, give the number of member
def get_index(n):
    if n == 0:
        return [0, 0]
    x = math.floor(np.log2(n))
    y = n - int(2**x)
    return [x, y]


# Convert value to index
def value_to_index(tree, value, single=True):
    if single:
        anode = get_node(tree, value)
        return anode.index
    else:
        indexes = []
        for val in value:
            anode = get_node(tree, val)
            indexes += [anode.index]
        return indexes


# Convert index to value
def index_to_value(tree, index, single=True):
    if single:
        anode = get_node(tree, index)
        return anode.value
    else:
        values = []
        for ind in index:
            anode = get_node(tree, ind)
            values += [anode.value]
        return values


# Get the public keys of the nodes in the node's copath
def get_pk_path(tree, node):
    public_keys = {index_to_value(tree, val): get_node(
        tree, val).public_key for val in node.path}
    return public_keys


# Node(s) in common between 'path1' and 'path2' lists
def common_node(path1, path2):
    common = []
    for node_ind in path1:
        if node_ind in path2:
            common += node_ind
    if common == []:
        raise Exception("No common nodes betwneen \
             {} and {}".format(path1, path2))
    return common


# Sort a path, from the highest to the lowest,
# meaning the deepest in the tree until the apex
def order_path(path):
    if isinstance(path[0], int):
        return path
    base_tens = []
    for node_ind in path:
        base_tens += [node_ind[0]*10 + node_ind[1]]
    order = np.array(base_tens).argsort()
    path = np.array(path)
    return path[order[::-1]]


# Give the deepest node
def get_highest_node(path):
    if isinstance(path[0], int):
        return path
    return order_path(path)[-1]



# Find the smallest node in common between user's copath
# and partner path, and return its value
def lowest_common_node(user, partner, tree):
    path_partner = get_node(tree, partner).path
    copath_user = get_node(tree, user).copath
    commun = common_node(path_partner, copath_user)   # Xe get the index
    return index_to_value(tree, commun)


def kdf(v1, v2, v3, pp, method):
    if method == 'sike27':
        z = v1*(v2+1)*(v3+3)
        w = (z*z.conj()).re
    elif method == "ecdh" or method == "SIKE751":
        w = v1*(v2+1)*(v3+3) % pp
    return w


# Get all the pubic keys quickly
def get_all_pk(anode):
    l_dico = {}
    if not anode.isLeaf:
        l_dico = get_all_pk(anode.children[0])
        r_dico = get_all_pk(anode.children[1])
        l_dico.update(r_dico)     # We merge the dicts
    l_dico.update({anode.value: anode.public_key})
    return l_dico


def read_tree(groupname):
    filename = "Tree_" + groupname + "_" + current_user.name + ".pkl"
    try:
        with open(filename, 'rb') as input_tree:
            tree = pickle.load(input_tree)
            return tree
    except Exception:
        Exception("Impossible to open the file {}".format(filename))


def write_tree(groupname, tree):
    filename = "Tree_" + groupname + "_" + current_user.name + ".pkl"
    try:
        with open(filename, 'wb') as output:
            pickle.dump(tree, output, pickle.HIGHEST_PROTOCOL)
    except Exception:
        Exception("Impossible to write the tree in file {}".format(filename))
