from email.policy import default
from importlib.resources import path
from pickle import load, dump
from pydoc import pathdirs
from tokenize import String
from types import NoneType
from unicodedata import name
from wsgiref.validate import validator
from click import confirm
from flask import Flask, redirect, render_template, flash, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, DateField, SelectMultipleField, SelectField
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
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
login_manager.login_message = 'User needs to be logged in to view this poop!'
login_manager.login_message_category = 'error'

@login_manager.user_loader
def load_user(user_id):
    return UserModel.query.get(int(user_id))

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=300)

#===========================FORMS=======================================

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

class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired()],
        render_kw={'autofocus' : True, 'placeholder': "Email:"}
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
        render_kw={ "placeholder": "Password"},
    )
    submit = SubmitField("Login")

class GroupForm(FlaskForm):
    group = StringField(
        "Group Name",
        validators=[DataRequired()],
        render_kw={'autofocus' : True, 'placeholder': "Email:"}
        )
    members = SelectMultipleField(
        "Members",
        choices=[('1', 'root'), ('2', 'Bjerke')],
        coerce=int
    )

class FolderForm(FlaskForm):
    itemname = StringField(
        "ItemName",
        validators=[DataRequired(), Length(max=50)],
        render_kw={'autofocus' : True, 'placeholder': "Item name"}
    )
    private = SelectField(
        "Private",
        choices=[(0,"Public"),(1,"Private")],
        default=(0,"Public"),
        coerce=int
    )
    r_groups = SelectMultipleField(
        "Groups with read Privilages",
        choices=[(3,"All Users"), (1,"Test Group")],
        coerce=int
    )
    rw_groups = SelectMultipleField(
        "Groups with read and write Privilages",
        choices=[(3,"All Users"), (1,"Test Group")],
        coerce=int
    )
    submit = SubmitField("Create")



class FileForm(FlaskForm):
    pass

class EditFileForm(FlaskForm):
    pass


db = SQLAlchemy(app)

#===========================TABLES======================================

class UserModel(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True) #"Auto Increment"
    name = db.Column(db.String(150), nullable = False) #"Ola Normann"
    email = db.Column(db.String(150), nullable = False, unique = True) #"example@domain.cocaine"
    password_hash = db.Column(db.String(150), nullable=False) #"skdhfjdshfo"
    groups = db.Column(db.String(150), nullable = False) #"0,1,2,3..."

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
    itemname = db.Column(db.String(250), nullable = False) #"filnavn(.filtype om fil)~uuid"
    path = db.Column(db.String(500), nullable = False) #"./mappe1/mappe2/mappe3/"
    private = db.Column(db.Boolean)#0 = public  :  1 = Private
    group_privs = db.Column(db.PickleType)#lagra privs i dictionaries ved å bruk pickle (var = pickle.dumps(innhold) / pickle.loads(var)) Pickle Rick :D ඞ

#===========================FUNCTIONS===================================

def PermissionHandler(required_priv, object):
    user_groups = current_user.groups.split(",")
    group_privs = pickle.loads(object.group_privs) 
    for group, priv in group_privs.items():
        if (str(group) in user_groups and required_priv in priv) or "1" in user_groups or object.owner == current_user.id:
            return True
    return False

def GetAvaliableName_helper(path, name):
    name_number = GetAvaliableName(path, name, 1) 
    added = "(" + str(name_number) + ")"
    return name + added

def GetAvaliableName(path, name, iteration):
    item = ItemModel.query.filter_by(path = path, itemname = name + "(" + str(iteration) + ")").first()
    if item is None:
        return iteration
    else:
        iteration += 1
        return GetAvaliableName(path, name, iteration) 


#===========================ROUTES======================================

@app.route('/')
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('item', path = '.-', name = 'Mappe'))
    if form.validate_on_submit():
        email = UserModel.query.filter_by(email = form.email.data).first()
        if email:
            #check hashpass
            if check_password_hash(email.password_hash, form.password.data):
                login_user(email)
                flash('Login was successfull', 'success')
                return redirect(url_for('item', path = '.-', name = 'Mappe'))
            else:
                flash('Incorrect password','error')
        else:
            flash('User does not exist','error')
    return render_template("login.html", form=form, loginpage=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('User has been logget out', 'success')
    return (redirect(url_for('login')))

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
            return redirect(url_for('login'))
        else:
            flash('Email already exists', 'error')
            return render_template('register.html', form=form)
    flash(str(form.errors).strip('{}'), 'error')
    return render_template("register.html", form=form)
            
@app.route('/item/<string:path>/<string:name>')
@login_required
def item(path,name):
    item = ItemModel.query.filter_by(path = path, itemname = name).first()
    print(item)
    if isinstance(item, NoneType):
        return redirect(url_for('previous', path = path))
    match item.type:
        case 0:#Show contents of folder
            unchecked_contents = ItemModel.query.filter_by(path = f"{item.path}{item.itemname.split('~')[0]}-")
            contents = []
            for items in unchecked_contents:
                #if PermissionHandler("r", items):
                if True:
                    #owner_id = items.owner
                    #owner_name =  UserModel.query.filter_by(id = owner_id).first().name
                    #items.owner = owner_name
                    contents.append(items)
            return render_template('folder.html', contents = contents, current_folder = item, viewing=True)
        case 1:
            pass
        
@app.route('/previous/<string:path>')
#JINJA url_for('previous', path = current_folder.path)
def previous(path):
    if path == '.-':
        return redirect(url_for('item', path = '.-', name = 'Mappe'))
    print(path)
    path_list = path.split("-")
    previous_path = ""
    for part in path_list[:-2]:
        previous_path = previous_path + part + "-"
        print(previous_path)
    return redirect(url_for('item', path = previous_path, name = path_list[-2:-1]))

@app.route("/newfolder/<string:path>/<string:parent>", methods=['GET','POST'])
#JINJA url_for('newfolder', path=current_folder.path, parent=current_folder.itemname)
@login_required
def newfolder(path, parent):
    form = FolderForm()
    if form.validate_on_submit():
        itempath = path + parent +"-"
        item = ItemModel.query.filter_by(path = itempath, itemname = form.itemname.data).first()
        if item is None:
            foldername = form.itemname.data
        else:
            foldername = GetAvaliableName_helper(itempath, form.itemname.data) #checks for itemname(n), until it finds an avaliable number
        group_priv_dict = {}
        for group in form.r_groups.data:
            group_priv_dict[group] = "r"
        for group in form.rw_groups.data:
            group_priv_dict[group] = "rw"
        newfolder = ItemModel(
            owner = current_user.id,
            type = 0,
            itemname = foldername,
            path = itempath,
            private = form.private.data,
            group_privs = group_priv_dict
        )
        db.session.add(newfolder)
        db.session.commit()
        flash('Folder created succesfully', 'success')
        return redirect(url_for('item', path=itempath, name=foldername))
    flash(str(form.errors).strip('{}'), 'error')
    return render_template("newfolder.html", form=form)
    
        
        
            






#På bunnj
if __name__ == "__main__":
    app.run(debug=True)