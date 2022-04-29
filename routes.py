from forms import *
from types import NoneType
from flask import Flask, redirect, render_template, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import date, timedelta
from werkzeug.utils import secure_filename
import uuid as uuid
import os
from flask_wtf.file import FileField, FileAllowed, FileRequired

#index redirects to login
@app.route('/')
def index():
    return redirect(url_for("login"))

#login user
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
            unchecked_contents = ItemModel.query.filter_by(path = f"{item.path}{item.itemname.split('~')[0]}-")
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
    if path == '.-':
        return redirect(url_for('item', path = '.-', name = 'Mappe'))
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
            itemname = foldername.strip("~-"),
            path = itempath,
            private = form.private.data,
            group_privs = group_priv_dict
        )
        db.session.add(newfolder)
        db.session.commit()
        flash('Folder created succesfully', 'success')
        return redirect(url_for('item', path=itempath, name=foldername))
    return render_template("newfolder.html", form=form)