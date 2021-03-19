from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pickle
import ast
from hashlib import sha256
import requests
from numpy import random
from mysike import eA, p, SIKE_compute_pk
from mysike import Complex, convert_Complex, createSS, server_address
from base64 import b64encode, b64decode
from flask_login import current_user
from classes import Group, Party
from time import sleep
from db_func import get_otk, get_priv_id, names_n_group, get_token


# eA = 5
# eB = 4
# p = (2**eA)*(3**eB) - 1
# # A =  2j


# PA = [(2261+1260j), (1389+2448j)]
# QA = [(818+1952j), (741+2039j)]
# PB = [(584+2292j), (774+2529j)]
# QB = [(1982+1795j), (1865+2542j)]
# A = 6


def get_key_aes(sender, recipient, info_otk=None):
    names, groupnames = names_n_group(sender)
    if recipient in names:
        keyy = P2Psecret(sender, recipient, "receiver", info_otk)
    elif recipient in groupnames:
        print("Arbre de ", current_user.name, ": " +
              'Tree_'+recipient+"_"+current_user.name)
        with open('Tree_'+recipient+"_"+current_user.name+'.pkl',
                  'rb') as input_tree:
            tree = pickle.load(input_tree)
        keyy = tree.private_key
        print('keyy = ', keyy)
        stage_key = Group.query.filter_by(
            groupname=recipient).first().prevStageKey
        keyy = kdfAES(keyy, Complex(stage_key), p)
    else:
        raise Exception("Problème avec {} : ni parmi {}, \
                        ni parmi {}".format(recipient, names, groupnames))
    return keyy


def P2Psecret(user, partner, side, public_key=None, method="sike27"):
    if side == "sender":
        private_otk = random.randint(1, 2**eA)
        headers = {'x-access-tokens': get_token(current_user.name)}
        otk_bundle = requests.get(server_address + "/getOTK/" + partner
                                  + "/" + str(-1), headers=headers).json()

        if method == "sike27":
            public_otk = convert_Complex(
                        ast.literal_eval(otk_bundle['publOTK']))
        elif method == "ecdh" or method == "SIKE751":
            if method == "SIKE751":
                sleep(0.00487)
            public_otk = ast.literal_eval(otk_bundle['publOTK'])

        dico = {'creatorOTK': SIKE_compute_pk(private_otk, 'initiator'),
                'partnerOTK': otk_bundle['indexOTK']}

        secret_key = createSS(public_otk, private_otk, 'initiator', method)
        return secret_key, dico

    elif side == "receiver":
        public_key = ast.literal_eval(public_key)
        pOTK = get_otk(partner, int(public_key['partnerOTK']), delete=True)

        private_otk = pOTK.privateOTK
        public_otk = convert_Complex(public_key['creatorOTK'])

        secret_key = createSS(public_otk, private_otk, 'receiver', method)
        return secret_key


# The key is a string, extended to the correct size with SHA-256
def encrypt_aes(plain_text, password):
    print("\n{} est encrypté avec {}".format(plain_text, password))
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = sha256(password.encode('utf-8')).digest()

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(
        bytes(plain_text, 'utf-8'))
    ciphertext = b64encode(cipher_text).decode('utf-8')
    print('ciphertext = ', ciphertext)
    return {
        'cipher_text': ciphertext,
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt_aes(ciphertext, password):
    # decode the dictionary entries from base64
    enc_dict = ast.literal_eval(ciphertext)
    cipher_text = b64decode(enc_dict['cipher_text'])
    print("\n{} est decrypté avec {}".format(enc_dict['cipher_text'],
                                             password))
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])

    # generate the private key from the password and salt
    private_key = sha256(password.encode('utf-8')).digest()

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted.decode()


def kdfAES(v1, v2, pp):
    z = v1*(v2+1)
    w = (z*z.conj()).re
    return w


def X3DH(user, partner, side, OTKeys, method="sike27"):
    priv_id = get_priv_id(user)
    otk = get_otk(user, serverID=OTKeys['privateOTK'])
    priv_otk = otk.privateOTK

    if method == "sike27":
        # Here, the side asked is the inverse than the one in the parameters
        otherside = 'initiator' if side == 'receiver' else 'receiver'
        public_id = Party.query.filter_by(
            name=user, target=partner, side=otherside).first().publicID

        public_id = convert_Complex(ast.literal_eval(public_id))
        public_otk = convert_Complex(ast.literal_eval(OTKeys['publicOTK']))

        # print("\nPour {} - {}, on a :".format(user, partner))
        # print('public_id :', public_id, '- priv_otk :', priv_otk)
        # print('publicOTK :', public_otk, '- priv_id :', priv_id)

        # public ID + secret OTK
        ss1 = createSS(public_id, priv_otk, side=side, method=method)
        # public OTK + secret ID
        ss2 = createSS(public_otk, priv_id, side=side, method=method)
        # public OTK + secret ID
        ss3 = createSS(public_otk, priv_otk, side=side, method=method)
    elif method == "ecdh" or method == "SIKE751":
        otherside = 'initiator' if side == 'receiver' else 'receiver'
        public_id = Party.query.filter_by(
            name=user, target=partner, side=otherside).first().publicID
        public_id = ast.literal_eval(public_id)
        public_otk = ast.literal_eval(OTKeys['publicOTK'])
        # public ID + secret OTK
        ss1 = createSS(public_id, priv_otk, method=method)
        # public OTK + secret ID
        ss2 = createSS(public_otk, priv_id, method=method)
        # public OTK + secret ID
        ss3 = createSS(public_otk, priv_otk, method=method)

        if side == "initiator":
            return [ord(ss1[0]), ord(ss2[0]), ord(ss3[0])]
        else:
            return [ord(ss2[0]), ord(ss1[0]), ord(ss3[0])]

    # According to the situation (sender or receiver)
    # we adapt the order
    if side == "initiator":
        return [ss1, ss2, ss3]
    else:
        return [ss2, ss1, ss3]
