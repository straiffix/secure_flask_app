# -*- coding: utf-8 -*-

from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
import time
from . import db
import re

auth = Blueprint('auth', __name__)
failed_log =0

def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/login', methods=['POST'])
def login_post():
    #email = request.form.get('email')
    global failed_log
    name = request.form.get('name')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
    time.sleep(1)
    user = User.query.filter_by(name=name).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password): 
        flash(f'Please check your login details and try again. Your attempt: {failed_log+1}')
        failed_log +=1
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup', methods=['POST'])
def signup_post():
    name = request.form.get('name')
    password = request.form.get('password')
    check = password_check(password)
    if check['password_ok'] is False:
        message = "Your password is weak. You should check: "
        if check['length_error'] is True:
            message += "password length (it should be at least 8 symbols); "
        if check['digit_error'] is True:
            message += "if you have any numbers; "
        if check['uppercase_error'] is True:
            message += "if you have any uppercase letters; "
        if check['lowercase_error'] is True:
            message +=" if you have any lowercase letters; "
        if check['symbol_error'] is True:
            message +=" if you have any specific symbols; "
        flash(message)
        
        return redirect(url_for('auth.signup'))
            
    user = User.query.filter_by(name=name).first() # if this returns a user, then the name already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('User already exists')
        return redirect(url_for('auth.signup'))

    # create new user with the form data. Hash the password so plaintext version isn't saved.
    new_user = User(name=name, password=generate_password_hash(password, method='pbkdf2:sha256:10000', salt_length=8))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

#@auth.route('/signup')
#def signup():
#    return render_template('signup.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    global failed_log
    failed_log = 0
    return redirect(url_for('main.index'))