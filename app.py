from forms import *
from types import NoneType
from flask import Flask, redirect, render_template, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import date, datetime, timedelta
from flask_wtf.file import FileField, FileAllowed, FileRequired
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
ADMINGROUP=2
ALLUSERSGROUP=1
TESTGROUP=3


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
    itemname = db.Column(db.String(250), nullable = False) #"filnavn(.filtype om fil)~uuid"
    owner = db.Column(db.Integer, db.ForeignKey('users.id')) #fk til users id
    post_date = db.Column(db.DateTime, nullable = False)#date posted
    edited_date = db.Column(db.DateTime, nullable = False)
    type = db.Column(db.Boolean)#0 = mappe : 1 = fil
    path = db.Column(db.String(500), nullable = False) #"./mappe1/mappe2/mappe3/"
    group_privs = db.Column(db.PickleType)#lagra privs i dictionaries ved å bruk pickle (var = pickle.dumps(innhold) / pickle.loads(var)) Pickle Rick :D 
    tags = db.Column(db.String(500))#py list with id of tags where [] are replaced with ',' ",0,1,60,89,"

class CommentsModel(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key = True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'))#fk to Items id, that has the comment section.
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))#fk to users id, to know who made the comment
    comment = db.Column(db.String(150), nullable=False) #comment text
    date = db.Column(db.DateTime, nullable = False)#date posted

class TagModel(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(50), nullable=False)#name of tag f.ex: Documentation



#===========================FUNCTIONS===================================

def PermissionHandler(required_priv, object):
    user_groups = current_user.groups.split(",")
    group_privs = object.group_privs
    for group, priv in group_privs.items():
        if (str(group) in user_groups and required_priv in priv) or str(ADMINGROUP) in user_groups or object.owner == current_user.id:
            return True
    return False

def PermissionCreator(form, group_priv_dict = {}):
    for group in form.r_groups.data:
        group_priv_dict[group] = "r"
    for group in form.rw_groups.data:
        group_priv_dict[group] = "rw"
    match form.private.data:
        case 0:
            group_priv_dict[ALLUSERSGROUP] = 'r'
        case 1:
            group_priv_dict[ALLUSERSGROUP] = 'DELETION'
            group_priv_dict.pop(ALLUSERSGROUP)
    return group_priv_dict

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

#index redirects to login
@app.route('/')
def index():
    return redirect(url_for("login"))

#login user
@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('item', path = 'root', name = '-'))
    if form.validate_on_submit():
        email = UserModel.query.filter_by(email = form.email.data).first()
        if email:
            #check hashpass
            if check_password_hash(email.password_hash, form.password.data):
                login_user(email)
                flash('Login was successfull', 'success')
                return redirect(url_for('item', path = 'root', name = '-'))
            else:
                flash('Incorrect password','error')
        else:
            flash('User does not exist','error')
    return render_template("login.html", form=form, loginpage=True)

#logout user
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('User has been logget out', 'success')
    return (redirect(url_for('login')))

#Register new user
@app.route("/register", methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = UserModel.query.filter_by(email = form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password.data, 'sha256')
            grouplist = form.groups.data
            grouplist.append(ALLUSERSGROUP)#adds all users group
            group_str = str(grouplist).strip("[]")
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

#Display a file or folder
@app.route('/item/<string:path>/<string:name>')
@login_required
def item(path,name):
    item = ItemModel.query.filter_by(path = path, itemname = name).first()
    print(item)
    if isinstance(item, NoneType):
        return redirect(url_for('previous', path = path))
    match item.type:
        case 0:#Show contents of folder
            unchecked_contents = ItemModel.query.filter_by(path = f"{item.path}{item.itemname.strip('-').split('~')[0]}-")
            contents = []
            for items in unchecked_contents:
                if PermissionHandler("r", items):
                    #owner_id = items.owner
                    #owner_name =  UserModel.query.filter_by(id = owner_id).first().name
                    #items.owner = owner_name
                    contents.append(items)
            return render_template('folder.html', contents = contents, current_folder = item, viewing=True)
        case 1:
            pass

#Return to parent folder      
@app.route('/previous/<string:path>')
#JINJA url_for('previous', path = current_folder.path)
@login_required
def previous(path):
    if path == 'root-':
        return redirect(url_for('item', path = 'root', name = '-'))
    print(path)
    path_list = path.split("-")
    previous_path = ""
    for part in path_list[:-2]:
        previous_path = previous_path + part + "-"
        print(previous_path)
    return redirect(url_for('item', path = previous_path, name = path_list[-2:-1]))

#New Folder


@app.route("/newfolder/<string:path>/<string:parent>", methods=['GET','POST'])
#JINJA url_for('newfolder', path=current_folder.path, parent=current_folder.itemname)
@login_required
def newfolder(path, parent):
    form = FolderForm()
    if form.validate_on_submit():
        parent = parent.strip('-')
        itempath = path + parent +"-"
        item = ItemModel.query.filter_by(path = itempath, itemname = form.itemname.data).first()
        if item is None:
            foldername = form.itemname.data
        else:
            foldername = GetAvaliableName_helper(itempath, form.itemname.data) #checks for itemname(n), until it finds an avaliable number
        group_priv_dict = PermissionCreator(form)
        newfolder = ItemModel(
            owner = current_user.id,
            type = 0,
            itemname = foldername.strip("~-"),
            path = itempath,
            group_privs = group_priv_dict,
            post_date = datetime.now(),
            edited_date = datetime.now()
        )
        db.session.add(newfolder)
        db.session.commit()
        flash('Folder created succesfully', 'success')
        return redirect(url_for('item', path=itempath, name=foldername))
    return render_template("newfolder.html", form=form)

#På bunnj
if __name__ == "__main__":
    app.run(debug=True)