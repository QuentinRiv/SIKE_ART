
from flask_login import UserMixin
from appli import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    privID = db.Column(db.Integer, nullable=False)
    token = db.Column(db.String(500))

    def __repr__(self):
        return '<User %r>' % self.name


# Public infos about other members
class Party(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(50), nullable=False)
    publicID = db.Column(db.String(500), nullable=False)
    side = db.Column(db.String(30), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Key %r>' % self.username


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(50), nullable=False)
    sender = db.Column(db.String(50), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    recipient = db.Column(db.String(500), default="")
    # Goal of 'owner' : when someone connects, the server
    # gives them their messages, without thinking about it

    def __repr__(self):
        return "<Message {}, from {}>".format(self.id, self.sender)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(50), nullable=False, primary_key=True)
    groupname = db.Column(db.String(50), nullable=False)
    members = db.Column(db.String(200), nullable=False)
    prevStageKey = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return "<Group {}>".format(self.groupname)


class OneTimeKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(50), nullable=False)
    privateOTK = db.Column(db.Integer, nullable=False)
    serverID = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return "<OTK of {}".format(self.owner)
