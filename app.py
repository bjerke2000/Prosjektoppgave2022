from contextlib import redirect_stderr
import os
import uuid as uuid
from datetime import date, datetime, timedelta
from types import NoneType
from sqlalchemy import nullslast, update
from flask import Flask, flash, redirect, render_template, session, url_for, request
from flask_mail import Mail, Message
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user, AnonymousUserMixin)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.ext.mutable import Mutable
import socket
from forms import *
from random import randint
from re import split

app = Flask(__name__)
app.config["SECRET_KEY"] = "esketit"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "mysql+pymysql://stud_v22_didriksenchr:R275uX1WYcttAKhb@kark.uit.no/stud_v22_didriksenchr"
app.config['MAIL_SERVER'] = 'smtpserver.uit.no'
app.config['MAIL_PORT'] = 587

UPLOAD_FOLDER = 'static/content'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ADMINGROUP=2
ALLUSERSGROUP=1
TESTGROUP=3
DELETED_USER=8


# Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'User needs to be logged in to view this!'
login_manager.login_message_category = 'error'


@login_manager.user_loader
def load_user(user_id):
    return UserModel.query.get(int(user_id))


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=300)


db = SQLAlchemy(app)
#===========================Mutable support=============================
#Fixing of tracking for pickle object
#https://docs.sqlalchemy.org/en/14/orm/extensions/mutable.html

class MyMutableType(Mutable):
    def __getstate__(self):
        d = self.__dict__.copy()
        d.pop('_parents', None)
        return d

class MutableDict(Mutable, dict):
    @classmethod
    def coerce(cls, key, value):
        if not isinstance(value, MutableDict):
            if isinstance(value, dict):
                return MutableDict(value)
            return Mutable.coerce(key, value)
        else:
            return value

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.changed()

    def __delitem__(self, key):
        dict.__delitem__(self, key)
        self.changed()
    
    def __getstate__(self):
        return dict(self)

    def __setstate__(self, state):
        self.update(state)

class PickleClass(object):
    pass #Support 

# ===========================TABLES======================================


class UserModel(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)  # "Auto Increment"
    name = db.Column(db.String(150), nullable=False)  # "Ola Normann"
    email = db.Column(db.String(150), nullable=False,
                      unique=True)  # "example@domain.cocaine"
    password_hash = db.Column(db.String(150), nullable=False)  # "skdhfjdshfo"
    groups = db.Column(db.String(150), nullable=False)  # "0,1,2,3..."

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
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True)
    group = db.Column(db.String(150), nullable=False,
                      unique=True)  # unike gruppenavn

    def __init__(self, group):
        self.group = group

class ItemModel(db.Model):
    __tablename__ = 'item'
    id = db.Column(db.Integer, primary_key=True)
    itemname = db.Column(db.String(250), nullable = False) #"filnavn(.filtype om fil)~uuid"
    owner = db.Column(db.Integer, db.ForeignKey('user.id')) #fk til users id
    post_date = db.Column(db.DateTime, nullable = False)#date posted
    edited_date = db.Column(db.DateTime, nullable = False)
    type = db.Column(db.Boolean)#0 = mappe : 1 = fil
    description = db.Column(db.String(500), nullable = True)
    path = db.Column(db.String(500), nullable = False) #"./mappe1/mappe2/mappe3/"
    group_privs = db.Column(MutableDict.as_mutable(db.PickleType))#lagra privs i dictionaries ved ?? bruk pickle (var = pickle.dumps(innhold) / pickle.loads(var)) Pickle Rick :D
    tags = db.Column(db.String(500))#py list with id of tags where [] are replaced with ',' ",0,1,60,89,"
    hitcount = db.Column(db.Integer)
    private = 0
    editable = False
    ownername = ''
    filetype = ''
    content = ''
    groups = ''
    named_tags =''

db.mapper(PickleClass, ItemModel) #part of mutable support 

class CommentsModel(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key = True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))#fk to Items id, that has the comment section.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))#fk to users id, to know who made the comment
    comment = db.Column(db.String(150), nullable=False) #comment text
    date = db.Column(db.DateTime, nullable = False)#date posted
    deleted = db.Column(db.Boolean)#0 not deleted, 1 deleted
    username = ''

class TagModel(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key=True)
    # name of tag f.ex: Documentation
    tag = db.Column(db.String(50), nullable=False)

#===========================FUNCTIONS===================================
class Anonymous(AnonymousUserMixin):
  def __init__(self):
    self.id = 0
    self.groups = ',1,'
    self.registerform = EmailVerify()

login_manager.anonymous_user = Anonymous
#===========================FUNCTIONS===================================

def PermissionHandler(required_priv, object): #Checks if the current user has the given priv for an item
    user_groups = current_user.groups.split(",")
    group_privs = object.group_privs
    if object.owner == current_user.id:
        return True
    for group, priv in group_privs.items():
        if (str(group) in user_groups and required_priv in priv) or str(ADMINGROUP) in user_groups:
            return True
    return False

def PermissionCreator(form, group_priv_dict={}): #Makes priv dictionairy from input lists
    for group in form.r_groups.data:
        group_priv_dict[group] = "r"
    for group in form.rw_groups.data:
        group_priv_dict[group] = "rw"
    for group in group_priv_dict.keys():
        if group not in form.rw_groups.data and group not in form.r_groups.data:
            group_priv_dict[group]='none'
    if form.private.data == 0:
            group_priv_dict[ALLUSERSGROUP] = 'r'
    elif form.private.data == 1:
            group_priv_dict[ALLUSERSGROUP] = 'none'
    return group_priv_dict

def GetAvaliableName_helper(path, name):#Starts GetAvaliableName
    name_number = GetAvaliableName(path, name, 1)
    added = "(" + str(name_number) + ")"
    return name + added

def GetAvaliableName(path, name, iteration): #Iterates through all folders with the same name in a list, until it gets an avaliable name
    item = ItemModel.query.filter_by(
        path=path, itemname=name + "(" + str(iteration) + ")").first()
    if item is None:
        return iteration
    else:
        iteration += 1
        return GetAvaliableName(path, name, iteration)

def ItemInfoLoader(item, isitemroute=False):
    text_types = ['txt']
    picture_types=['jpg','png','jpeg','gif']
    video_types=['mp4','webm']
    item.ownername = UserModel.query.filter_by(id = item.owner).first().name
    for group ,priv in item.group_privs.items():
        if priv != 'none':
            item.groups += item.groups + GroupModel.query.filter_by(id = group).first().group + ','
    item.groups = item.groups[:-1]
    if item.group_privs[ALLUSERSGROUP] != 'none':
        item.private = 0
    else:
        item.private = 1
    item.editable = PermissionHandler('rw',item)
    if item.type == 1:
        for tag_id in item.tags.split(',')[1:-1]:
            item.named_tags = item.named_tags + TagModel.query.filter_by(id=tag_id).first().tag + ','
        item.named_tags = item.named_tags[:-1]
        type = item.itemname.split('~')[1].split('.')[-1] #Gets filetype
        if type in text_types:
            if isitemroute:
                with open(os.path.join(app.config['UPLOAD_FOLDER'], item.itemname), 'r', encoding='utf-8', newline='\n') as f:
                        lines = f.readlines()
                item.content=lines
            item.filetype = 'text'
        elif type in picture_types:
                item.filetype = 'picture'
        elif type in video_types:
                item.filetype = 'video'
    return item

def TagManager(tags): #if tag already exists: append id to list, else: create tag and retrieve recieved id and append to list
    tags = tags.split(',')
    cleaned_tags = []
    final_tag_str = ','
    for tag in tags:
        temptag=''
        cleaned_tags.append(temptag.join(letter for letter in tag if letter.isalnum()).lower()) #Remove all special charactes and set them to lower case
    current_tags = TagModel.query.all()#Get all tags
    for tag in current_tags:
        if tag.tag in cleaned_tags: #Check if tag already exists
            final_tag_str = final_tag_str + f'{tag.id},'
            cleaned_tags.remove(tag.tag)
    for tag in cleaned_tags:#add tag if it does not exist
        newtag = TagModel(tag = tag)
        db.session.add(newtag)
    db.session.commit()
    newtags = TagModel.query.filter(TagModel.tag.in_(cleaned_tags)).all()#get new tag objects
    for tag in newtags:
        final_tag_str = final_tag_str + f'{tag.id},' #ad new tag's id's to str
    return final_tag_str

def DeleteItem(id):#Deletes item and all comments attatched
    comments = CommentsModel.query.filter_by(item_id = id)
    item = ItemModel.query.filter_by(id = id).first()
    for comment in comments:
        comment.deleted = 1
    path = item.path
    name = item.itemname
    db.session.delete(item)
    db.session.commit()
    return path

def DeleteUser(id): #Deletes a user and reassigns all items and comments from the user to [DELETED USER]
    comments = CommentsModel.query.filter_by(user_id = id)
    items = ItemModel.query.filter_by(owner = id)
    for comment in comments:
        comment.user_id = DELETED_USER
    for item in items:
        item.owner = DELETED_USER
    db.session.commit()
    user = UserModel.query.filter_by(id = id).first()
    db.session.delete(user)
    db.session.commit()

def DeleteComment(id): #Deletes a comment and returns parent for routing purposes
    comment = CommentsModel.query.filter_by(id=id).first()
    parentitem = ItemModel.query.filter_by(id=comment.item_id).first()
    comment.deleted = 1
    db.session.commit()
    return parentitem.path, parentitem.itemname

def DeleteTag(id): #Deletes Tags and removes tag from all affected items
    items = ItemModel.query.filter_by(type = 1)
    for item in items:
        if ','+str(id)+',' in item.tags:
            item.tags = item.tags.replace(','+str(id)+',',',')
    tag = TagModel.query.filter_by(id = id).first()
    db.session.delete(tag)
    db.session.commit()

def DeleteGroupMember(user, group):
    user_object = UserModel.query.filter_by(id = user).first()
    user_object.groups = user_object.groups.replace(f',{group},',',')
    db.session.commit()

def DeleteGroup(id):
    for user in UserModel.query.all():
        if ','+ str(id) +',' in user.groups:
            user.groups = user.groups.replace(f',{id},',',')
    for item in ItemModel.query.all():
        if id in item.group_privs:
            item.group_privs[id]='none'
    db.session.commit()
    group = GroupModel.query.filter_by(id=id).first()
    db.session.delete(group)
    db.session.commit()

def AdminTest():
    if str(ADMINGROUP) in current_user.groups.split(','):
        return True
    return False

def GroupManagerLoader(groups):
    groups_dict = {}
    group_members_dict={}
    for id in groups.split(',')[1:-1]:
        groups_dict[id] = GroupModel.query.filter_by(id = int(id)).first().group
    users = UserModel.query.all()
    if str(ADMINGROUP) not in groups_dict:
        groups_dict.pop(str(ALLUSERSGROUP))
    for group in groups_dict.keys():
        group_members_dict[group]=[]
        for user in users:
            if group in user.groups.split(',')[1:-1]:
                group_members_dict[group].append((user.id, user.name))
    return group_members_dict,  groups_dict

def GroupTupleManager():
    groups = [(g.id, g.group) for g in GroupModel.query.order_by('group')][2:] #Exclude first two values since they are admin and all users
    final_group = []
    for group in groups:
        if current_user.is_authenticated:
            for g in current_user.groups.split(',')[1:-1]:
                if g == str(group[0]):
                    final_group.append(group)
        else:
            final_group.append(group)
    return(final_group)

def NewGroup(groupname, members):
        newgroup = GroupModel(
            group = groupname
        )
        db.session.add(newgroup)
        membersdata = members.split(',')
        if current_user.email not in members:
            membersdata.append(current_user.id)
        for email in membersdata:
            user = UserModel.query.filter_by(email = email).first()
            user.groups = user.groups + str(GroupModel.query.filter_by(group = groupname).first().id) +','
        db.session.commit()

#===========================ROUTES======================================

# index redirects to login
@app.route('/')
def index():
    return redirect(url_for('item', path = 'root', name = '-'))

# login user
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('item', path = 'root', name = '-'))
    if form.validate_on_submit():
        email = UserModel.query.filter_by(email=form.email.data).first()
        if email:
            # check hashpass
            if check_password_hash(email.password_hash, form.password.data):
                login_user(email)
                flash('Login was successfull', 'success')
                return redirect(url_for('item', path = 'root', name = '-'))
            else:
                flash('Incorrect password', 'error')
        else:
            flash('User does not exist', 'error')
    return render_template("login.html", form=form, loginpage=True)

# logout user
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('User has been logged out', 'success')
    return (redirect(url_for('login')))

# Register new user
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    form.groups.choices = GroupTupleManager()
    emailform = EmailVerify()
    if form.validate_on_submit() or emailform.validate_on_submit():
        user = UserModel.query.filter_by(email=form.email.data).first()
        if user is None:
            if emailform.validate_on_submit():
                    if emailform.verify_code.data == str(emailform.code.data):
                        groupstr = emailform.groups.data
                        if len(groupstr) > 0:
                            groupstr = groupstr + ','
                        group_str = ',' + str(ALLUSERSGROUP) + ',' + groupstr
                        user = UserModel(name=emailform.name.data,
                                         email=emailform.email.data,
                                         password_hash=emailform.password_hash.data,
                                         groups=group_str
                                         )
                        db.session.add(user)
                        db.session.commit()
                        return redirect(url_for('login'))
                    flash('Incorrect code')
                    return render_template('verify.html', form = emailform)
            hashed_pw = generate_password_hash(form.password.data, 'sha256')
            code = randint(100000, 999999)
            emailformdata = EmailVerifyHiddenLoader(code , form.name.data, form.email.data, hashed_pw, form.groups.data)
            emailform.populate_obj=emailformdata
            emailform.password_hash.data = hashed_pw
            emailform.groups.data = str(form.groups.data).strip('[]')
            emailform.code.data=str(code)
            mail = Mail(app)
            msg = Message('test mail', sender='Knut.Collin@uit.no', recipients =[form.email.data])
            msg.body = 'Plain text body'
            msg.html = 'HTML <b>Bekreft epostadresse med kode:</b>' + str(code)
            with app.app_context():
              mail.send(msg)
            return render_template('verify.html', form = emailform)
        else:
            flash('Email already exists', 'error')
            return render_template('register.html', form=form)
    return render_template("register.html", form=form)

#administrative page
@app.route('/admin', methods=['GET','POST'])
@login_required
def admin():
    if str(ADMINGROUP) in current_user.groups.split(','):
        Users = UserModel.query.all()
        Groups = GroupModel.query.all()
        Items = ItemModel.query.all()
        for item in Items:
            ItemInfoLoader(item)
        Comments = CommentsModel.query.all()
        for comment in Comments:
            comment.username = UserModel.query.filter_by(id = comment.user_id).first().name
        Tags = TagModel.query.all()
        return render_template('admin.html', users = Users, groups = Groups, items = Items, comments = Comments, tags = Tags, admin = AdminTest())
    return redirect(url_for('index'))

#Display a file or folder
@app.route('/item/<string:path>/<string:name>', methods=['GET','POST'])
def item(path, name):
    item = ItemModel.query.filter_by(path=path, itemname=name).first()
    if isinstance(item, NoneType):
        return redirect(url_for('previous', path=path))
    item.hitcount += 1
    db.session.commit()
    if item.type == 0: #Show contents of folder
            searchform = SearchForm()
            if searchform.validate_on_submit():
                return redirect(url_for('search', keywords = searchform.searchfield.data))
            path = item.path.replace('-','/')[4:]+item.itemname.replace('-','/')
            unchecked_contents = ItemModel.query.filter_by(path = f"{item.path}{item.itemname.strip('-').split('~')[0]}-")
            contents = []
            for items in unchecked_contents:
                if PermissionHandler("r", items):
                    ItemInfoLoader(items)
                    contents.append(items)
            return render_template('folder.html', contents = contents, current_folder = item, viewing=True, folder=True, path = path, admin = AdminTest(), searchform = searchform)

    elif item.type == 1: #Show contents if file
            path = item.path.replace('-','/')[4:]+item.itemname.split('~')[1]
            ItemInfoLoader(item, True)
            if item.filetype == '':
                flash('Not able to open file')
                return redirect(url_for('previous', path = path))
            commentform = CommentForm()
            if commentform.validate_on_submit():
                newcomment = CommentsModel(
                    item_id = item.id,
                    user_id = current_user.id,
                    comment = commentform.comment.data,
                    date = datetime.now(),
                    deleted = 0
                )
                db.session.add(newcomment)
                db.session.commit()
                return redirect(url_for('item', path=item.path, name=item.itemname))
            comments = CommentsModel.query.filter_by(item_id = item.id).all()
            for comment in comments:
                comment.username = UserModel.query.filter_by(id = comment.user_id).first().name
            return render_template('file.html', item = item, comments = comments, commentform = commentform, current_folder = item, viewing = True, path = path, comment_amount=len(comments) ,admin = AdminTest())

#Return to parent folder
@app.route('/previous/<string:path>')
# JINJA url_for('previous', path = current_folder.path)
@login_required
def previous(path):
    if path == 'root' or 'root-': #Catch exceptions when working close to root
        return redirect(url_for('item', path = 'root', name = '-'))
    print(path)
    path_list = path.split("-")
    previous_path = ""
    for part in path_list[:-2]:
        previous_path = previous_path + part + "-"
        print(previous_path)
    return redirect(url_for('item', path=previous_path, name=path_list[-2:-1]))

@app.route('/search/<string:keywords>', methods=['GET','POST'])
def search(keywords):
    searchform = SearchForm()
    if searchform.validate_on_submit():
        return redirect(url_for('search', keywords = searchform.searchfield.data))
    keyword_list = split(', | |; ', keywords)
    tag_hits=[]
    for word in keyword_list:
        tag_hits = tag_hits + TagModel.query.filter(TagModel.tag.like(f'%{word}%')).all()
    item_hits = []
    for word in keyword_list:
        item_hits = item_hits + ItemModel.query.filter(ItemModel.itemname.like(f'%{word}%')).all()
    for tag in tag_hits:
        item_hits = item_hits + ItemModel.query.filter(ItemModel.tags.like(f'%,{tag.id},%')).all()
    else:
        content = set(item_hits)
    for item in content:
        ItemInfoLoader(item)
    return render_template('folder.html', contents = content,  folder=True, admin = AdminTest(), searchform = searchform)

#New Folder
@app.route("/newfolder/<string:path>/<string:parent>", methods=['GET','POST'])
#JINJA url_for('newfolder', path=current_folder.path, parent=current_folder.itemname)*
@login_required
def newfolder(path, parent):
    form = FolderForm()
    groups = GroupTupleManager()
    form.r_groups.choices = groups
    form.rw_groups.choices = groups
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
    return render_template("newfolder.html", form=form, admin = AdminTest())

@app.route("/addfile/<string:path>/<string:parent>", methods=['GET','POST'])
def addfile(path, parent):
    form = FileForm()
    groups = GroupTupleManager()
    form.r_groups.choices = groups
    form.rw_groups.choices = groups
    if form.validate_on_submit():
        parent = parent.strip('-')
        itempath = path + parent +"-"
        tags = TagManager(form.tags.data)
        if form.name.data != '':
            itemname = secure_filename(form.name.data + '.' + form.file.data.filename.split('.')[-1])
        else:
            itemname = secure_filename(form.file.data.filename)
        itemname_uuid = str(uuid.uuid1()) + '~' + itemname.strip('-')
        form.file.data.save(os.path.join(app.config['UPLOAD_FOLDER'], itemname_uuid))
        group_priv_dict = PermissionCreator(form)
        newitem = ItemModel(
            owner = current_user.id,
            type = 1,
            itemname = itemname_uuid,
            description = form.description.data,
            path = itempath,
            group_privs = group_priv_dict,
            post_date = datetime.now(),
            edited_date = datetime.now(),
            tags = tags
        )
        db.session.add(newitem)
        db.session.commit()
        flash('Item created succesfully', 'success')
        return redirect(url_for('item', path=itempath, name=itemname))
    return render_template("additem.html", form=form, admin = AdminTest())

@app.route('/delcomment/<int:id>', methods=['GET','POST'])
def delcomment(id):
    deletion = DeleteComment(id)
    return redirect(url_for('item', path=deletion[0], name=deletion[1]))

@app.route('/admin_delete/<string:table>/<int:id>')
@login_required
def admin_delete(table, id):
    if AdminTest():
        if table == 'users':
                DeleteUser(id)
                flash(f'User succesfully deleted', 'success')
        elif table == 'items':
                DeleteItem(id)
                flash(f'Item succesfully deleted', 'success')
        elif table == 'groups':
                DeleteGroup(id)
                flash('Group succesfully deleted', 'success')
        elif table == 'tags':
                DeleteTag(id)
                flash(f'Tag succesfully deleted', 'success')
        elif table == 'comments':
                DeleteComment(id)
                flash(f'Comment succesfully deleted', 'success')             
        return redirect(url_for('admin'))
    return redirect(url_for('index'))
    
@app.route('/edituser', methods=['GET','POST'])
@login_required
def edituser():
    object = UserEditLoader(current_user.name)
    form = UserEditForm(obj = object)
    form.groups.choices = [(g.id, g.group) for g in GroupModel.query.order_by('group')][2:] #Exclude first two values since they are admin and all users
    if form.validate_on_submit():
        user = UserModel.query.filter_by(id=current_user.id).first()
        if form.password.data != '':
            hashed_pw = generate_password_hash(form.password.data, 'sha256')
            user.password_hash = hashed_pw
        user.name = form.name.data
        groups =[ALLUSERSGROUP]
        groups = groups + form.groups.data
        user.groups = ',' + str(groups).strip('[]') + ','
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edituser.html', form=form)

@app.route('/usergroupmanagement', methods=['POST','GET'])
@login_required
def usergroupmanagement(): #Shows groups that user is apart of
    groupform = GroupForm()
    info = GroupManagerLoader(current_user.groups)
    members = [(u.id, u.name) for u in UserModel.query.order_by('name')] #Exclude first value since it is root user
    members.remove((1,'root'))#Removes root user from list
    members.remove((DELETED_USER,'[DELETED USER]')) #Removes Deleted user from list 
    groupform.members.choices = members
    if groupform.validate_on_submit():
        if GroupModel.query.filter_by(group = groupform.group.data).first() is None:
            NewGroup(groupform.group.data, groupform.members.data)
            return redirect(url_for('usergroupmanagement'))
        else:
            flash('Group already exists', 'error')
    return render_template('groupmanagement.html', groups_dict = info[1], group_members_dict = info[0], groupform = groupform, route='user', admin = AdminTest())

@app.route('/admingroupmanagement', methods=['POST','GET'])
@login_required
def admingroupmanagement(): #Shows all groups
    if AdminTest():
        groupform = GroupForm()
        groups = ','
        for group in GroupModel.query.all():
            groups = groups + str(group.id)+','
        info = GroupManagerLoader(groups)
        if groupform.validate_on_submit():
            if GroupModel.query.filter_by(group = groupform.group.data).first() is None:
                NewGroup(groupform.group.data, groupform.members.data)
                return redirect(url_for('admingroupmanagement'))
            else:
                flash('Group already exists', 'error')
        return render_template('groupmanagement.html', groups_dict = info[1], group_members_dict = info[0], groupform = groupform, route='admin', admin = AdminTest())
    return redirect(url_for('item', path = 'root', name = '-'))

@app.route('/remove_group_member/<int:user>/<int:group>/<string:route>')
@login_required
def remove_group_member(user, group, route):
    DeleteGroupMember(user, group)
    return redirect(url_for(f'{route}groupmanagement'))

@app.route('/edit/<string:path>/<string:name>', methods=['GET','POST'])
@login_required
def edit(path, name):
    item = ItemModel.query.filter_by(path=path, itemname=name).first()
    groups = GroupTupleManager()
    if item.itemname.split('.')[-1] in ['txt']:
        ItemInfoLoader(item, True)
        object = EditTextFileFormLoader(item.content , item.description ,item.named_tags, list(item.group_privs.keys()) , item.private)
        form = EditTextFileForm(obj=object)
        text = True
    else:
        ItemInfoLoader(item)
        object = EditFileFormLoader(item.description ,item.named_tags, list(item.group_privs.keys()) , item.private)
        form = EditFileForm(obj=object)
        text = False
    form.r_groups.choices = groups
    form.rw_groups.choices = groups
    if form.validate_on_submit():
        if text:
            with open(os.path.join(app.config['UPLOAD_FOLDER'], item.itemname), 'w', encoding='utf-8', newline='\n') as f:
                f.write(form.text.data)
        item.description = form.description.data
        item.tags = TagManager(form.tags.data)
        item.group_privs = PermissionCreator(form, item.group_privs)
        item.edited_date = datetime.now()
        db.session.commit()
        flash('Changes Saved', 'success')
        return redirect(url_for('item', path=item.path, name=item.itemname))
    return render_template('edit.html', form = form, item=item, text = text)

@app.route('/delete_item/<int:id>')
@login_required
def delete_item(id):
    path = DeleteItem(id)
    return redirect(url_for('previous', path = path))

#P?? bunnj
if __name__ == "__main__":
    app.run(debug=True)
