from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, DateField, SelectMultipleField, SelectField
from wtforms.validators import DataRequired, EqualTo, Length, Email

ADMINGROUP=2
ALLUSERSGROUP=1
TESTGROUP=3

class RegisterForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[DataRequired(), Length(max=150)],
        render_kw={"autofocus":True, "placeholder": "name"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Length(max=150), Email()],
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
        choices= [(ADMINGROUP,'Admin'),(TESTGROUP,'Test Group')],
        coerce=int
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
        choices=[(TESTGROUP,"Test Group")],
        coerce=int
    )
    rw_groups = SelectMultipleField(
        "Groups with read and write Privilages",
        choices=[(TESTGROUP,"Test Group")],
        coerce=int
    )
    submit = SubmitField("Create")

class FileForm(FlaskForm):
    pass

class EditFileForm(FlaskForm):
    pass
