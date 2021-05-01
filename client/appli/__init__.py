from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS


db = SQLAlchemy()


def init_app():
    app = Flask(__name__, instance_relative_config=False, static_folder=None)
    app.config.from_pyfile('settings.py')
    CORS(app, supports_credentials=True)

    db.init_app(app)

    with app.app_context():
        # from . import routes
        from .login.routes import login_bp
        from .tree.routes import tree_bp
        from .message.routes import message_bp
        from .info.routes import info_bp

        # Register Blueprints
        app.register_blueprint(login_bp)
        app.register_blueprint(tree_bp)
        app.register_blueprint(message_bp)
        app.register_blueprint(info_bp)

        db.create_all()
        print("\n***********\nDatabase created\n")

        return app
