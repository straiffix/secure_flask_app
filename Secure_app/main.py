# -*- coding: utf-8 -*-

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from .models import Private_notes, Public_notes
from .auth import password_check
from . import db

main = Blueprint('main', __name__)


#context = SSL.Context(SSL.PROTOCOL_TLSv1_2)
#context.use_privatekey_file('certs/test.key')
#context.use_certificate_file('certs/test.crt')


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/changepass')
@login_required
def changepass():
    return render_template('changepass.html')

@main.route('/changepass', methods=['POST'])
@login_required
def change_pass_post():
    user = current_user
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
        return redirect(url_for('main.changepass'))
    user.password = password=generate_password_hash(password, method='pbkdf2:sha256:10000', salt_length=8)
    db.session.add(user)
    db.session.commit()
    flash('Password has been updated')
    return redirect(url_for('main.profile'))


@main.route('/profile', methods=['POST'])
@login_required
def profile_post():
    #email = request.form.get('email')
    note = request.form.get('message')
    private = True if request.form.get('private') else False

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if private is True:
        new_note= Private_notes(name=current_user.name, note=note)
    else:
        new_note= Public_notes(name=current_user.name, note=note)
        

    # add the new user to the database
    db.session.add(new_note)
    db.session.commit()
    
    return redirect(url_for('main.profile'))

@main.route('/profile')
@login_required
def profile():
#    list_of_private_notes = "<h2>Private notes</h2>"
    list_of_private_notes = []
    for priv_n in Private_notes.query.filter_by(name=current_user.name):
#        list_of_private_notes += "<div class = \"priv_note\"> <p><strong>" + current_user.name + "</strong>" + priv_n.note + "</p></div
        list_of_private_notes.append({'user': current_user.name, 'post': priv_n.note})
        
#    list_of_public_notes = "<h2>Public notes</h2>"
    list_of_public_notes = []
    for pub_n in Public_notes.query:
#        list_of_public_notes += "<div class = \"pub_note\"> <p><strong>" + pub_n.name + "</strong>" + pub_n.note + "</p></div>"
        list_of_public_notes.append({'user': pub_n.name, 'post': pub_n.note})
#    
    return render_template('profile.html', name=current_user.name, 
                           list_of_private_notes=list_of_private_notes, 
                           list_of_public_notes=list_of_public_notes)
    
