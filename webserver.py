from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload
from models import Base, User, Catalog, Item
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g, abort
from flask_httpauth import HTTPBasicAuth
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import InputRequired,  Length
from flask import session as login_session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_marshmallow import Marshmallow
import json

WTF_CSRF_ENABLED = False
auth = HTTPBasicAuth()


app = Flask(__name__)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
ma = Marshmallow(app)
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

    return render_template('viewitems.html', categories=categories, catalog=catalog, items=items, items_count=items_count)


"""View details of a particular item. If the creator is current user then show edit and delete links."""


@app.route('/catalog/<string:cat_name>/<string:item_name>/')
def showCatalogItem(cat_name, item_name):

    # Get all categories for sidepanel

    catalog = session.query(Catalog).all()

    # Get selected item

    item = session.query(Item).filter_by(name=item_name).one()

    # If creator show edit and delete features
    if login_session['user_id'] and str(item.user_id) in login_session['user_id']:
        return render_template('showitem.html', catalog=catalog, cat_name=cat_name, item=item, item_name=item.name)

    return render_template('item-no-edit.html', catalog=catalog, cat_name=cat_name, item=item, item_name=item.name)


"""Allows a logged in user to create an item"""


@app.route('/catalog/add-item/', methods=['GET', 'POST'])
@login_required
def addItemToCategory():

    if request.method == 'GET':
        catalog = session.query(Catalog).all()
        return render_template('additem.html', catalog=catalog)

    elif request.method == 'POST':

        # Get data from request

        cat_id = request.form['categoryid']
        name = request.form['itemName']
        description = request.form['description']
        user_id = login_session['user_id']

        # Create new Item
        newItem = Item(name=name, description=description, catalog_id=cat_id, user_id=user_id)

        # Commit item to database
        session.add(newItem)
        session.commit()
        flash('Item Created')
        return redirect(url_for('showCatalog'))


"""Allow logged in users to edit their own items"""


@app.route('/catalog/<string:item_name>/edit/', methods=['GET', 'POST'])
@login_required
def editItem(item_name):

    # Get all categories for sidepanel

    category = session.query(Catalog).all()

    # Find the selected item

    item = session.query(Item).filter_by(name=item_name).one()

    if request.method == 'GET':
        return render_template('edititem.html', category=category, item=item)

    elif request.method == 'POST':

        # Check to see if the user created the item

        if login_session['user_id'] == item.user_id:

            # Set new item attributes

            name = request.form['itemName']
            description = request.form['description']
            category = request.form['categoryid']
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


"""Delete an item if the current user is creator of item"""


@app.route('/catalog/<string:item_name>/delete/', methods=['GET', 'POST'])
def deleteItem(item_name):

    # Get selected item
    item = session.query(Item).filter_by(name=item_name).one()

    # Check to see if current user is item creator

    if login_session['user_id'] and str(item.user_id) in login_session['user_id']:

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

    if request.method == 'GET':

        return render_template('signup.html')

    elif request.method == 'POST':

        # Get data from form

        username = request.form['userName']
        password = request.form['password']

        # Check for empty data
        if username is not None and password is not None:

            # Hash password  and create new user

            hashed_password = generate_password_hash(password, method='sha256')
            user = User(username=username, hash_password=hashed_password)

            # Commit user data to database
            session.add(user)
            session.commit()

            # Set up session variables and login user

            login_session['username'] = username
            login_session['user_id'] = user.id
            login_user(user)
            flash('Account Created')

            return redirect(url_for('showCatalog'))
        else:
            flash('You Must Provide Username And Password')
            return redirect(url_for('registerNewUser'))


"""Allow users to login if form data is valid"""


@app.route('/login/', methods=['GET', 'POST'])
def showLogin():

    # Create login form
    form = LoginForm()

    # If form submitted and valid

    if form.validate_on_submit():

        # find the user

        user = session.query(User).filter_by(username=form.username.data).first()

        # If user found

        if user is not None:

            # Verify password

            if check_password_hash(user.hash_password, form.password.data):

                # Setup session data and redirect user

                login_session['username'] = user.username
                login_session['user_id'] = user.id
                login_user(user)

                flash('Your Are Now Logged In')
                return redirect(url_for('showCatalog'))
            else:
                flash('Username Or Password Invalid')
                return redirect(url_for('showLogin'))

    return render_template('login.html', form=form)


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
    logout_user()
    login_session['username'] = None
    login_session['user_id'] = None
    flash('Your Are Now Logged Out')
    return redirect(url_for('showCatalog'))


@app.route('/accounts/JSON/')
@login_required
def getAllAccounts():
    categories = session.query(Catalog).options(joinedload(Catalog.items)).all()
    return jsonify(dict(Catalog=[dict(c.serializable, items=[i.serializable for i in c.items]) for c in categories]))



@app.route('/categories/JSON/')
@login_required
def getAllCategories():
    categories = session.query(Catalog).all()
    items = session.query(Item).all()


@app.route('/items/JSON/')
@login_required
def getAllItems():
    items = session.query(Item).all()
    return jsonify(Item=[r.serializable for r in items])




class LoginForm(Form):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=1, max=80)])
    submit = SubmitField("Send")


class ItemForm(Form):
    itemName = StringField('itemName', validators=[InputRequired(), Length(min=1, max=20)])
    category = StringField('category', validators=[InputRequired()])
    description = PasswordField('description', validators=[InputRequired()])
    submit = SubmitField("Submit")





if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
