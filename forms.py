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

class EmailVerifyHiddenLoader():
    def __init__(self,code, name, email, password_hash, groups) -> None:
        self.verify_code = str(code)
        self.code = str(code)
        self.name = str(name)
        self.email = email
        self.password_hash = str(password_hash)
        self.groups = str(groups)

class EmailVerify(FlaskForm):
    name = HiddenField('name')
    email = HiddenField('email')
    password_hash = HiddenField('password_hash')
    groups = HiddenField('groups')
    code = HiddenField('code')
    verify_code = StringField('Verification-code',
        validators=[DataRequired(),Length(min=6,max=6)],
        render_kw={'placeholder':'verification-code', 'autofocus':True}
    )
    submit = SubmitField('Verify')

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
    validators=[DataRequired(), Length(max=150)],
    render_kw={'resize':'none', 'placeholder':'Description...'}
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
    def __init__(self, description, named_tags, groups, private) -> None:
        self.description = description
        self.tags = named_tags
        self.r_groups = groups
        self.rw_groups = groups
        self.private = private

class EditFileForm(FlaskForm):
    description = StringField('Textarea',
    widget=TextArea(),
    validators=[DataRequired(), Length(max=150)],
    render_kw={'resize':'none', 'placeholder':'Description...'}
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
    def __init__(self,lines, description, named_tags, groups, private) -> None:
        br_lines = ''
        for line in lines:
            br_lines = br_lines + line.strip('[]')
        self.description = description
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
    validators=[DataRequired(), Length(max=150)],
    render_kw={'resize':'none', 'placeholder':'Description...'}
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
    render_kw={'placeholder':'Comment'}
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

class SearchForm(FlaskForm):
    searchfield = StringField('Searchfield',
    render_kw={'placeholder':'filename or tags separated by comma...'}
    )
    submit = SubmitField('Search')

class UserEditLoader():
    def __init__(self, name) -> None:
        self.name = name

class UserEditForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[DataRequired(), Length(max=150)],
        render_kw={"autofocus":True, "placeholder": "name"},
    )
    password = PasswordField(
        "Password",
        validators=[EqualTo("password_confirm", "Passwords do not match")],
        render_kw={"placeholder":"Password"}
    )
    password_confirm = PasswordField(
        "Confirm password",
        render_kw={"placeholder":"Confirm password"}
    )
    groups = SelectMultipleField(
        "Select Field",
        coerce=int
    )
    submit = SubmitField("Register")