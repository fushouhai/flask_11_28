from flask import render_template, redirect, request, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, ForgetPasswordForm, FPNewPasswordForm, \
      ChangeEmailPasswordConfirmForm, ChangeEmailSetForm
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.':    
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_passwd.data):
            current_user.password = form.new_passwd.data
            flash('Password changed!')
            return redirect(url_for('main.index'))
        flash('Invalid password.')
    return render_template('auth/change_password.html', form=form)

@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    form = ChangeEmailPasswordConfirmForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            return redirect(url_for('auth.change_email_set'))
        else:
            flash('password error')
            return redirect(url_for('main.index'))
    return render_template('auth/change_email_password_confirm.html', form=form)

@auth.route('/change_email_set', methods=['GET', 'POST'])
@login_required
def change_email_set():
    form = ChangeEmailSetForm()
    if form.validate_on_submit():
        token = current_user.generate_confirmation_token(email=form.email.data)
        send_email(form.email.data, 'Confirm', 
                   'auth/email/change_email_set', user=current_user, token=token)
        flash('A confirm email has been sent to you by new email')
        return redirect(url_for('main.index'))
    return render_template('auth/change_email_set.html', form=form)

@auth.route('/change_email_set_done/<token>')
@login_required
def change_email_set_done(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        flash('confirm error!')
        return redirect(url_for('main.index'))
    if current_user.id == data.get('confirm'):
        current_user.email = data.get('email')
        current_user.avatar_hash = hashlib.md5(
          current_user.email.encode('utf-8')).hexdigest()
        flash('email changed')
        return redirect(url_for('main.index'))
    flash('user changed or logout')
    return redirect(url_for('main.index'))
    
@auth.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    form = ForgetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            token = user.generate_confirmation_token()
            send_email(user.email, 'Confirm Your Account',
                       'auth/email/forget_password', user=user, token=token)
            flash('A confirmation email has been sent to you by email, which is about forgetting password')
            return redirect(url_for('main.index'))
    return render_template('auth/forget_password.html', form=form)
 
@auth.route('/confirm_forget_password/<token>')
def confirm_forget_password(token):
    session['token'] = token
    return redirect(url_for('auth.forget_password_set_password'))

@auth.route('/forget_password_set_password', methods=['GET', 'POST'])
def forget_password_set_password():
    form = FPNewPasswordForm()
    if form.validate_on_submit():
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            token = session.get('token')
            data = s.loads(token)
        except:
            flash('confirm error!')
            return redirect(url_for('main.index'))
        val_id = data.get('confirm')
        if val_id is not None:
            user = User.query.filter_by(id=val_id).first()
            if user is not None:
                user.password = form.password.data
                db.session.add(user)  
                db.session.commit()             
                flash('password has changed!')
                return redirect(url_for('auth.login'))
            else:
                flash('can not find user!')
                return redirect(url_for('main.index'))
        else:
            flash('user is error!')
            return redirect(url_for('main.index'))
    return render_template('auth/forget_password_set_password.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    flash('Warning:Email@163.com does not work!')
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))
