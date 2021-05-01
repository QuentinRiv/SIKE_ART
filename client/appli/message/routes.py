from werkzeug.utils import secure_filename
import requests
from datetime import datetime

from flask import render_template, request
from flask import jsonify, url_for, Blueprint

from flask_login import login_required, current_user

from appli.info.mysike import server_address

from appli.info.classes import Message, Party
from appli.info.db_func import add_db, get_mail_db
from appli.info.db_func import get_members, get_token
from appli.info.db_func import get_id, names_n_group, get_last_messages
from .cryptom import encrypt_aes, get_key_aes, P2Psecret
from appli.info.update_app import check_db
from appli.login.routes import still_connected


message_bp = Blueprint('message_bp', __name__,
                       template_folder='templates',
                       static_folder='static',
                       static_url_path="/appli/message/static/")


# Return the messages of 'partner'
@message_bp.route('/getmessages/<partner>')
@login_required
@still_connected
def get_messages(partner):

    # Check for new info
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

        direction = "sent" if mess.sender == current_user.name else "replies"

        sender_id = get_id(mess.sender, string=True)
        message = {"sender": sender_id,
                   "recipient": mess.recipient,
                   "content": mess.content,
                   "time": mess.time.time().strftime("%H:%M:%S"),
                   "direction": direction,
                   "imgURL": url_for('tree_bp.static',
                                     filename='/imag/' + mess.sender + '.png')}
        message_js += [message]

    return {'messages': message_js, 'members': members, 'id': partner_id}


@message_bp.route('/sendmessage', methods=["POST"])
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

    # Key is different if it's a group message
    # or 2-party message
    if recipient in groupnames:
        key = get_key_aes(sender, recipient)
    elif recipient in names:
        key, dico = P2Psecret(sender, recipient, 'sender')
        data['info_otk'] = repr(dico)
    else:
        raise Exception("Problem : the recipient name : {}".format(recipient))

    # Ciphertext
    encrypted_data = encrypt_aes(data['content'], str(key))
    data['content'] = repr(encrypted_data)

    headers = {'x-access-tokens': get_token(current_user.name)}
    requests.post(server_address + "/mailbox", json=data, headers=headers)

    return jsonify(answer="Génial")


# Prepare the page that shows all the messages
@message_bp.route('/messenger')
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

        partner_id = get_id(partner, string=True)

        try:
            if mail.sender == current_user.name:
                direction = "sent"
            else:
                direction = "received"

            message = {"sender": mail.sender,
                       "recipient": mail.recipient,
                       "content": mail.content,
                       "time": mail.time.time().strftime("%H:%M:%S"),
                       "direction": direction,
                       "imgURL": url_for('tree_bp.static',
                                         filename='imag/' + partner_id
                                                          + '.png'),
                       "partner": partner}

            partner_id = get_id(partner, string=True)

            message_js += [message]
        except Exception:
            raise ValueError("Error")

    return render_template('messenger.html', lastmails=message_js,
                           current=my_id, groupnames=groupnames)


# Initiate a new 2-party conversation
@message_bp.route('/new_conversation')
@login_required
@still_connected
def new_conversation():

    check_db()
    lastmails = get_last_messages(current_user.name)
    partners = list(lastmails.keys())
    names, groupnames = names_n_group(current_user.name)
    names.remove(current_user.name)
    print('names = ', names)

    other_partners = [name for name in names if name not in partners]
    partners_id = [Party.query.filter_by(target=partner)
                              .first().user_id for partner in other_partners]
    others = dict(zip(partners_id, other_partners))
    return render_template('new_conversation.html',
                           others=others, partners_id=partners_id)
