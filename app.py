import datetime
from flask import Flask, request, jsonify, render_template
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from models import db, User, Certificate

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['DEBUG'] = True
app.config['ENV'] = 'development'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = 'secret-key'

db.init_app(app)
Migrate(app, db)
CORS(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if not email:
        return jsonify({"msg": "email is required"}), 400

    if not password:
        return jsonify({"msg": "password is required"}), 400

    user = User.query.filter_by(email=email).first()

    if user:
        return jsonify({"msg": "email already exists"}), 400

    user = User()
    user.name = request.json.get("name", "")
    user.email = email
    user.password = bcrypt.generate_password_hash(password)

    user.save()

    return jsonify({"succes": "Register successfully!, please Log in"}), 200

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if not email:
        return jsonify({"msg": "email is required"}), 400

    if not password:
        return jsonify({"msg": "password is required"}), 400

    user = User.query.filter_by(email=email, active=True).first()

    if not user:
        return jsonify({"msg": "email/password are incorrect"}), 400

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "email/password are incorrect"}), 400

    expires = datetime.timedelta(days=3)

    data = {
        "acces_token": create_access_token(identity=user.email, expires_delta=expires),
        "user": user.serialize()
    }
       

    return jsonify({"succes": "Log In successfully!", "data": data}), 200


if __name__ == "__main__":
    manager.run()