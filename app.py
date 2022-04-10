from importlib.resources import path
import pickle
from pydoc import pathdirs
from types import NoneType
from flask import Flask, redirect, render_template, flash, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, DateField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import date, timedelta
from werkzeug.utils import secure_filename
import uuid as uuid
import os
from flask_wtf.file import FileField, FileAllowed, FileRequired

app = Flask(__name__)
app.config["SECRET_KEY"] = "påskerally"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "mysql+pymysql://stud_v22_didriksenchr:R275uX1WYcttAKhb@kark.uit.no/stud_v22_didriksenchr"

UPLOAD_FOLDER = 'content'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True) #"0 AI"
    name = db.Column(db.String(150), nullable = False) #"Ola Normann"
    email = db.Column(db.String(150), nullable = False, unique = True) #"example@domain.cocaine"
    password_hash = db.Column(db.String(150), nullable = False) #"skdhfjdshfo"
    groups = db.Column(db.String(150), nullable = False) #"0,1,2,3..."

    def __init__(self, name, email, password_hash, groups):
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.groups = groups
    

    @property
    def groups(self):
        return self.groups.split(",") #konverter til liste med gruppe tilhørighet
    
    @groups.setter
    def groups(self, value):
        if isinstance(value, list):
            self.groups = str(value).strip("[]")
        elif isinstance(value, str):
            self.groups = value

    @property
    def password_hash(self):
        return AttributeError("Password_hash is not retrievable")
    
    @password_hash.setter
    def password_hash(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verifypassword(self, password):
        check_password_hash(self.password_hash, password)
        
class GroupModel(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    group = db.Column(db.String(150), nullable=False, unique = True) #unike gruppenavn
    default_privs = db.Column(db.String(4), nullable = False) #r/rw/none

    def __init__(self, group, default_privs):
        self.group = group
        self.default_privs = default_privs

class ItemModel(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, db.ForeignKey('users.id')) #fk til users id
    type = db.Column(db.Boolean)#0 = mappe : 1 = fil
    itemname = db.Column(db.String(250), nullable = False) #"filnavn(.filtype om fil)_uuid"
    path = db.Column(db.String(500), nullable = False) #"./mappe1/mappe2/mappe3/"
    private = db.Column(db.Boolean)#0 = public  :  1 = Private
    group_privs = db.Column(db.PickleType)#lagra privs i dictionaries ved å bruk pickle (var = pickle.dumps(innhold) / pickle.loads(var)) Pickle Rick :D ඞ

def PermissionHandler(required_priv, object):
    user_groups = current_user.groups.split(",")
    group_privs = pickle.loads(object.group_privs)
    for group, priv in group_privs.items():
        if (str(group) in user_groups and required_priv in priv) or "1" in user_groups or object.owner == current_user.id:
            return True
    return False
        
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/item/<string:path>/<string:name>')
def item(path,name):
    item = ItemModel.query.filter_by(path = path, itemname = name).first()
    if isinstance(item, NoneType):
        return redirect(url_for('previous', path = path))
    match item.type:
        case 0:#Show contents of folder
            unchecked_contents = ItemModel.query.filter_by(path = f"{item.path}{item.itemname.split('_')[0]}-")
            contents = []
            for items in unchecked_contents:
                #if PermissionHandler("r", items):
                if True:
                    items.owner = UserModel.query.filter_by(id = items.owner).first().name
                    contents.append(items)
            return render_template('folder.html', contents = contents, current_folder = item)

@app.route('/previous/<string:path>')
def previous(path):
    print(path)
    path_list = path.split("-")
    previous_path = ""
    for part in path_list[:-2]:
        previous_path = previous_path + part + "-"
        print(previous_path)
    return redirect(url_for('item', path = previous_path, name = path_list[-2:-1]))
    
            







# Needs to be at the bottom
if __name__ == "__main__":
    app.run(debug=True)