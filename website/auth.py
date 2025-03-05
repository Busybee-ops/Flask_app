from flask import Blueprint, render_template, request, flash
from .models import User, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from flask_login import LoginManager 
import logging

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
         email = request.form.get('email')
         password = request.form.get('password')
         user = User.query.filter_by(email=email).first()
         if user:
            if check_password_hash(user.password, password):
                    flash("Logged in successfully!", category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.home'))
            else:
                    flash("Incorrect password, try again.", category='error')
         else:
                flash("Email does not exist.", category='error')
         
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
     logout_user()
     return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already exists.", category='error')
        elif len(email) < 4:
            flash("Email must be greater than 4 characters.", category='error')
        elif len(firstname) < 2:
            flash("First name must be greater than 1 character.", category='error')
        elif password1 != password2:
            flash("Passwords don't match.", category='error')
        elif len(password1) < 6:
            flash("Password must be at least 6 characters.", category='error')
        else:
            try:
                new_user = User(email=email, firstname=firstname, password=generate_password_hash(password1, method='pbkdf2:sha256'))
                db.session.add(new_user)
                db.session.commit()  # save the new user to the database
                login_user(new_user, remember=True)  # login the new user
                flash("Account created!", category='success')
                return redirect(url_for('views.home'))
            except Exception as e:
                db.session.rollback()
                flash("An error occurred while creating the account.", category='error')
                print(f"Error creating account for email {email}: {e}")

    return render_template("sign_up.html", user=current_user)
