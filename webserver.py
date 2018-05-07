from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from sqlalchemy.orm import sessionmaker, joinedload
from models import Base, User, Catalog, Item
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g, abort
from flask_httpauth import HTTPBasicAuth
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import InputRequired,  Length
from flask import session as login_session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
import httplib2
import requests
import random
import string

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

auth = HTTPBasicAuth()


app = Flask(__name__)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'showLogin'


engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/catalog/')
def showCatalog():
    catalog = session.query(Catalog).all()
    items = session.query(Item).all()
    return render_template('catalog.html', catalog=catalog, items=items)


"""View of items within a category"""


@app.route('/catalog/<string:cat_name>/items/')
def viewCategory(cat_name):

    # Get all categories for sidepanel

    categories = session.query(Catalog).all()

    # Get the selected category

    catalog = session.query(Catalog).filter_by(name=cat_name).one()

    # Get all catalog items from selected category and the total count

    items = session.query(Item).filter_by(catalog_id=catalog.id)
    items_count = session.query(Item).filter_by(catalog_id=catalog.id).count()

    return render_template('viewitems.html', categories=categories, catalog=catalog,
                           items=items, items_count=items_count)


"""View details of a particular item. If the creator is current user then show edit and delete links."""


@app.route('/catalog/<string:cat_name>/<string:item_name>/')
def showCatalogItem(cat_name, item_name):

    # Get all categories for sidepanel

    catalog = session.query(Catalog).all()

    # Get selected item

    item = session.query(Item).filter_by(name=item_name).one()

    # If creator show edit and delete features
    if login_session.get('user_id') is not None:
        if item.user_id == int(login_session['user_id']):
            return render_template('showitem.html', catalog=catalog, cat_name=cat_name,
                                   item=item, item_name=item.name)

    return render_template('item-no-edit.html', catalog=catalog, cat_name=cat_name, item=item, item_name=item.name)


"""Allows a logged in user to create an item"""


@app.route('/catalog/add-item/', methods=['GET', 'POST'])
@login_required
def addItemToCategory():

    # Create form

    form = ItemForm()

    # Get Categories for item selection

    catalog = session.query(Catalog).all()
    form.categoryid.choices = [(c.id, c.name) for c in catalog]

    if form.validate_on_submit():

        # Get data from request and current user id

        cat_id = form.categoryid.data
        name = form.itemName.data
        description = form.description.data
        user_id = login_session['user_id']

        # Create new Item

        newItem = Item(name=name, description=description, catalog_id=cat_id, user_id=user_id)

        # Commit item to database

        session.add(newItem)
        session.commit()
        flash('Item Created')
        return redirect(url_for('showCatalog'))

    else:
        return render_template('additem.html', catalog=catalog, form=form)


"""Allow logged in users to edit their own items"""


@app.route('/catalog/<string:item_name>/edit/', methods=['GET', 'POST'])
@login_required
def editItem(item_name):

    # Create form

    form = EditItemForm()

    # Get Categories for item selection

    catalog = session.query(Catalog).all()
    form.categoryid.choices = [(c.id, c.name) for c in catalog]

    # Find the selected item

    item = session.query(Item).filter_by(name=item_name).one()

    if form.validate_on_submit():

        # Check to see if the user created the item

        if int(login_session.get('user_id')) == item.user_id:

            # Set new item attributes

            name = form.itemName.data
            description = form.description.data
            category = form.categoryid.data
            item.catalog_id = category
            item.name = name
            item.user_id = login_session['user_id']
            item.description = description

            # Commit item and redirect

            session.add(item)
            session.commit()
            flash('Item Edited')
            return redirect(url_for('showCatalog'))

        else:
            flash('You cannot edit this item')
            return redirect(url_for('showCatalog'))

    return render_template('edititem.html', item=item, form=form)


"""Delete an item if the current user is creator of item"""


@app.route('/catalog/<string:item_name>/delete/', methods=['GET', 'POST'])
def deleteItem(item_name):

    # Get selected item

    item = session.query(Item).filter_by(name=item_name).one()

    # Check to see if current user is item creator

    if login_session.get('user_id') == item.user_id:

        # Delete selected item, set message and redirect user

        session.delete(item)
        session.commit()
        flash('Item Deleted')
        return redirect(url_for('showCatalog'))

    else:
        flash('You cannot edit this item')
        return redirect(url_for('showCatalog'))


"""Create new user"""


@app.route('/catalog/create-account/', methods=['GET', 'POST'])
def registerNewUser():

    # Check to see if user is logged in

    if current_user.is_authenticated:

        return redirect(url_for('showCatalog'))

    # Create form

    form = RegisterForm()

    if form.validate_on_submit():

        # Get data from form

        username = form.username.data
        password = form.password.data

        # Check for empty data

        if username is not None and password is not None:

            # Hash password  and create new user

            hashed_password = generate_password_hash(password, method='sha256')
            user = User(username=username, hash_password=hashed_password)

            # Commit user data to database

            try:
                # Set up session variables and login user

                login_session['username'] = user.username
                login_session['user_id'] = user.id
                login_session['provider'] = 'self'
                login_user(user)

                flash('Account Created')
                return redirect(url_for('showCatalog'))

            except IntegrityError:

                flash("User already exist.")
                return redirect(url_for('showCatalog'))

            except InvalidRequestError:

                flash("User already exist.")
                return redirect(url_for('showCatalog'))


    return render_template('signup.html', form=form)


"""Allow users to login if form data is valid"""


@app.route('/login/', methods=['GET', 'POST'])
def showLogin():

    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state

    # Check to see if user is logged in
    if current_user.is_authenticated:

        return redirect(url_for('showCatalog'))

    # Create login form
    form = LoginForm()

    # If form submitted and valid

    if form.validate_on_submit():

        # find the user

        user = session.query(User).filter_by(username=form.username.data).first()

        # If user found

        if user is not None:

            # Verify password

            if user.hash_password is not None:

                if check_password_hash(user.hash_password, form.password.data):

                    # Setup session data and redirect user

                    login_session['username'] = user.username
                    login_session['user_id'] = user.id
                    login_session['provider'] = 'self'
                    login_user(user)

                    flash('Your Are Now Logged In')
                    return redirect(url_for('showCatalog'))
                else:
                    flash('Username Or Password Invalid')
                    return redirect(url_for('showLogin'))
            else:
                flash('Username Or Password Invalid')
                return redirect(url_for('showLogin'))

    return render_template('login.html', form=form, STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session["username"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    # flash("you are now logged in as %s" % login_session['username'])
    return 'Welcome'


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('You are now logged out Google Account')
        login_session.pop('username', None)
        login_session.pop('user_id', None)
        login_session.pop('provider', None)
        return redirect(url_for('showCatalog'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    newUser = User(username=login_session['username'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(username=login_session['username']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(username):
    try:
        user = session.query(User).filter_by(username=username).one()
        return user.id
    except:
        return None


"""Callback to verify if user is logged in(LoginManger)"""


@login_manager.user_loader
def load_user(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    if user is not None:
        return user
    else:
        return None


"""Logout user and clear session data"""


@app.route('/logout/')
@login_required
def logout():

    if login_session['provider'] != 'self':

        if login_session['provider'] == 'google':

            return redirect(url_for('gdisconnect'))

        elif login_session['provider'] == 'facebook':

            return redirect(url_for('fbdisconnect'))

    else:
        logout_user()
        login_session.pop('username', None)
        login_session.pop('user_id', None)
        login_session.pop('provider', None)
        flash('Your Are Now Logged Out')
        return redirect(url_for('showCatalog'))


@app.route('/categories/JSON')
def categoriesJSON():
    catalog = session.query(Catalog).all()
    return jsonify(Categories=[r.serializable for r in catalog])


@app.route('/item/JSON')
def itemJSON():
    item = session.query(Item).filter_by(id=1)
    return jsonify(Item=[r.serializable for r in item])


@app.route('/catalog/JSON/')
@login_required
def getCatalog():
    categories = session.query(Catalog).options(joinedload(Catalog.items)).all()
    return jsonify(dict(Catalog=[dict(c.serializable, items=[i.serializable for i in c.items]) for c in categories]))


class LoginForm(Form):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=1, max=80)])
    submit = SubmitField("Send")


class RegisterForm(Form):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=1, max=80)])
    submit = SubmitField("Send")


class ItemForm(Form):
    itemName = StringField('itemName', validators=[InputRequired(), Length(min=1, max=20)])
    categoryid = SelectField('categoryid', validators=[InputRequired()], coerce=int)
    description = TextAreaField('description', validators=[InputRequired()])
    submit = SubmitField("Submit")


class EditItemForm(Form):
    itemName = StringField('itemName', validators=[InputRequired(), Length(min=1, max=20)])
    categoryid = SelectField('categoryid', validators=[InputRequired()], coerce=int)
    description = TextAreaField('description', validators=[InputRequired()])
    submit = SubmitField("Submit")


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='localhost', port=4996)
