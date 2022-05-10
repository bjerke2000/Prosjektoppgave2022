from ast import Sub
from tokenize import String
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, DateField, SelectMultipleField, SelectField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length, Email
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.widgets import TextArea

ADMINGROUP=2
ALLUSERSGROUP=1
TESTGROUP=3
text_types = ['txt']
picture_types=['jpg','png','jpeg','gif']
video_types=['mp4','webm']

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
        render_kw={'autofocus' : True, 'placeholder': "Email"}
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
        coerce=int
    )
    rw_groups = SelectMultipleField(
        "Groups with read and write Privilages",
        coerce=int
    )
    submit = SubmitField("Create")

class FileForm(FlaskForm):
    name = StringField('Name',
    render_kw={'placeholder':'Filename'}
    )
    file = FileField(
        'File', 
        validators=[FileRequired(), FileAllowed([*text_types,*picture_types,*video_types],'Non supported type')],
        render_kw={'placeholder':'Add file'}
        )
    description = StringField('Textarea',
    widget=TextArea(),
    render_kw={'resize':'none'}
    )
    tags = StringField(
        'Tags', 
        validators=[Length(max=50)], 
        render_kw={'placeholder':'Tags seperated by comma'}
        )
    r_groups = SelectMultipleField(
        "Groups with read Privilages",
        coerce=int
    )
    rw_groups = SelectMultipleField(
        "Groups with read and write Privilages",
        coerce=int
    )
    private = SelectField(
        "Private",
        choices=[(0,"Public"),(1,"Private")],
        default=(0,"Public"),
        coerce=int
    )
    submit = SubmitField('Upload')

class EditFileFormLoader():
    def __init__(self,named_tags, groups, private) -> None:
        self.tags = named_tags
        self.r_groups = groups
        self.rw_groups = groups
        self.private = private

class EditFileForm(FlaskForm):
    description = StringField('Textarea',
    widget=TextArea(),
    render_kw={'resize':'none'}
    )
    tags = StringField(
        'Tags', 
        validators=[Length(max=50)],
        render_kw={'placeholder':'Tags seperated by comma'}
        )
    r_groups = SelectMultipleField(
        "Groups with read Privilages",
        coerce=int
    )
    rw_groups = SelectMultipleField(
        "Groups with read and write Privilages",
        coerce=int
    )
    private = SelectField(
        "Private",
        choices=[(0,"Public"),(1,"Private")],
        coerce=int
    )
    submit = SubmitField('Save')

class EditTextFileFormLoader():
    def __init__(self,lines,named_tags, groups, private) -> None:
        br_lines = ''
        for line in lines:
            br_lines = br_lines + line.strip('[]')

        self.text = br_lines
        self.tags = named_tags
        self.r_groups = groups
        self.rw_groups = groups
        self.private = private

class EditTextFileForm(FlaskForm):
    text = StringField('Textarea',
    widget=TextArea(),
    render_kw={'resize':'none'}
    )
    description = StringField('Textarea',
    widget=TextArea(),
    render_kw={'resize':'none'}
    )
    tags = StringField(
        'Tags', 
        validators=[Length(max=50)],
        render_kw={'placeholder':'Tags seperated by comma'}
        )
    r_groups = SelectMultipleField(
        "Groups with read Privilages",
        coerce=int
    )
    rw_groups = SelectMultipleField(
        "Groups with read and write Privilages",
        coerce=int
    )
    private = SelectField(
        "Private",
        choices=[(0,"Public"),(1,"Private")],
        coerce=int
    )
    submit = SubmitField('Save')

class CommentForm(FlaskForm):
    comment = StringField('Comment',
    widget=TextArea(),
    validators=[DataRequired(), Length(max=150)],
    render_kw={'placeholder':'Write your comment here...'}
    )
    submit = SubmitField('Post')

class GroupForm(FlaskForm):
    group = StringField('Group name',
    validators=[DataRequired(), Length(max=50)],
    render_kw={'placeholder':'Groupname...'}
    )
    members = StringField('Member email',
        validators=[Length(max=500)],
        render_kw={'placeholder':'emails separated by ","'}
    )
    submit = SubmitField('Create Group')

class AddUserToGroupForm(FlaskForm):
    groupid = HiddenField('group_id')
    members = StringField('Member email',
        validators=[Length(max=500)],
        render_kw={'placeholder':'emails separated by ","'}
    )
    submit = SubmitField('Create Group')