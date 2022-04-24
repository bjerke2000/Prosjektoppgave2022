from importlib.resources import path
import pickle
from pydoc import pathdirs
from tokenize import String
from types import NoneType
from wsgiref.validate import validator
from click import confirm
from flask import Flask, redirect, render_template, flash, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, DateField, SelectMultipleField
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
app.config["SECRET_KEY"] = "esketit"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "mysql+pymysql://stud_v22_didriksenchr:R275uX1WYcttAKhb@kark.uit.no/stud_v22_didriksenchr"

UPLOAD_FOLDER = 'content'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Login
#login_manager = LoginManager()
#login_manager.init_app(app)
#login_manager.login_view='login'
#login_manager.login_message = 'User needs to be logged in to view this poop!'
#login_manager.login_message_category = 'error'

class RegisterForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[DataRequired(), Length(max=150)],
        render_kw={"autofocus":True, "placeholder": "name"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Length(max=150)],
        render_kw={"placeholder":"Email"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), EqualTo("password_confirm", "Passwords do not match")],
        render_kw={"placeholder":"Password"}
    )
    password_confirm = PasswordField(
        "Confirm password",
        validators=[DataRequired()],
        render_kw={"placeholder":"Confirm password"}
    )
    groups = SelectMultipleField(
        "Select Field",
        choices= [('0','All Users'), ('1','Admin')],
        coerce=str
    )
    submit = SubmitField("Register")

db = SQLAlchemy(app)

class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True) #"0 AI"
    password_hash = db.Column(db.String(150), nullable=False) #"skdhfjdshfo"
    groups = db.Column(db.String(150), nullable = False) #"0,1,2,3..."
    name = db.Column(db.String(150), nullable = False) #"Ola Normann"
    email = db.Column(db.String(150), nullable = False, unique = True) #"example@domain.cocaine"

    def __init__(self, name, email, password_hash, groups):
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.groups = groups
    

    @property
    def group(self):
        return self.groups
    
    @group.setter
    def group(self, value):
        self.groups = str(value).strip("[]")

    @property
    def password(self):
        return AttributeError("Password is not retrievable")
    
    @password.setter
    def password(self, password):
        self._password_hash = generate_password_hash(password, 'sha256')
    
    
    def VerifyPassword(self, password):
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
    print(item)
    if isinstance(item, NoneType):
        return redirect(url_for('previous', path = path))
    match item.type:
        case 0:#Show contents of folder
            unchecked_contents = ItemModel.query.filter_by(path = f"{item.path}{item.itemname.split('_')[0]}-")
            contents = []
            for items in unchecked_contents:
                #if PermissionHandler("r", items):
                if True:
                    #owner_id = items.owner
                    #owner_name =  UserModel.query.filter_by(id = owner_id).first().name
                    #items.owner = owner_name
                    contents.append(items)
            return render_template('folder.html', contents = contents, current_folder = item)
        case 1:
            pass

@app.route('/previous/<string:path>')
def previous(path):
    print(path)
    path_list = path.split("-")
    previous_path = ""
    for part in path_list[:-2]:
        previous_path = previous_path + part + "-"
        print(previous_path)
    return redirect(url_for('item', path = previous_path, name = path_list[-2:-1]))
    
@app.route("/register", methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = UserModel.query.filter_by(email = form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password.data, 'sha256')
            group_str = str(form.groups.data).strip("[]")
            user = UserModel(name = form.name.data,
                email = form.email.data,
                password_hash = hashed_pw,
                groups = group_str
            )
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash('Email already exists', 'error')
            return render_template('register.html', form=form)
    print (form.errors)
    return render_template("register.html", form=form)
            







# Needs to be at the bottom
if __name__ == "__main__":
    app.run(debug=True)