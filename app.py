from flask import Flask,render_template,request,session,abort,redirect,url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os.path
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import desc
from flask_mail import Mail, Message


app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
db_path = os.path.join(os.path.dirname(__file__), 'database.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'


mail=Mail(app)

app.config.update(
    DEBUG=True,
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='talha1503@gmail.com',
    MAIL_PASSWORD='insert password here'
    )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20),unique=True)
    email = db.Column(db.String(50),unique=True)
    password=db.Column(db.String(70))
    address = db.Column(db.String(150))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username',validators=[InputRequired(),Length(min=5,max=20)])
    password = StringField('password',validators=[InputRequired(),Length(min=8,max=70)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email',validators=[InputRequired(),Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=5, max=20)])
    password = StringField('password', validators=[InputRequired(), Length(min=8,max=70)])


#Signup page
@app.route('/signup',methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        if User.query.filter_by(username=form.username.data).first() == form.username.data:
            print("Username already exists")

        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit
        return redirect(url_for('login'))
    return render_template('signup.html', title='Signup', form=form)


#Home page
@app.route('/main')
@login_required
def homepage():
    if not session.get('logged_in'):
        return render_template('login.html',form=form)
    else:
        return render_template("mainpage.html",form=form)


#loginpage
@app.route('/login',methods =['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user,remember=form.remember.data)

                return redirect(url_for('main'))

    return render_template('login.html',title="Log in",form=form)


@app.route("/mail")
@login_required
def index():
    msg = Message('Customer Request', sender='talha1503@gmail.com', recipients=['trvt1234@gmail.com'])
    msg.body = "Request from customer regarding water quality testing is being forwarded."
    mail.send(msg)
    return render_template('successfull.html')


#logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return homepage()


if __name__ == '__main__':
    app.run(debug=True)

