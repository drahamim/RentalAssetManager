from flask import Blueprint
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from flask_security import roles_accepted
from src.conram.forms import UpdateForm
from src.conram.models import User, Role, db, Staff
from flask_bcrypt import Bcrypt
from datetime import datetime, timezone
from urllib.parse import urlparse

bp = Blueprint('auth', __name__, template_folder='templates')
bcrypt = Bcrypt()


def redirect_dest(fallback):
    dest = request.args.get('next')
    try:
        dest_url = dest
    except Exception:
        dest_url = fallback
    if dest is None:
        dest_url = fallback
    dest_url = dest_url.replace('\\', '')
    if not urlparse(dest_url).netloc and not urlparse(dest_url).scheme:
        return redirect(dest_url)
    return redirect(fallback)


@bp.route('/create/user', methods=['GET', 'POST'])
def user_create():
    if request.method == 'POST':
        user = User.query.filter_by(
            username=request.form['username']).first()
        email = User.query.filter_by(
            email=request.form['email']).first()

        if user or email:
            if user:
                msg = "User already exists"
            if email:
                msg = "User already exists with email"
            flash(msg, 'danger')
            return render_template('user_create.html', msg=msg)

        # Check if staff ID exists
        staff_info = Staff.query.filter_by(
            id=request.form['staff_id']).first()
        if not staff_info:
            msg = "Staff ID not found"
            flash(msg, 'danger')
            return render_template('user_create.html', msg=msg)

        # Check if passwords match
        if request.form['password'] != request.form['confirm_password']:
            msg = "Passwords do not match"
            flash(msg, 'danger')
            return render_template('user_create.html', msg=msg)

        user = User(username=request.form['username'],
                    staff_id=request.form['staff_id'],
                    email=request.form['email'],
                    password=bcrypt.generate_password_hash(
                        request.form['password']).decode('utf-8'))
        role = request.form['role']
        user.roles.append(Role.query.filter_by(name=role).first())
        user.active = True
        db.session.add(user)
        db.session.commit()
        flash('User successfully created.', 'success')
        return redirect(url_for('index'))
    return render_template('user_create.html')


@bp.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            db.session.query(User).filter_by(
                username=user.username).update(
                    {User.last_login: datetime.now(timezone.utc)})
            db.session.commit()
            flash('Logged in successfully.', 'success')
            return redirect_dest(fallback=url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return render_template('signin.html')
    return render_template('signin.html')


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.signin'))


@bp.route("/user/<user_id>")
@login_required
def my_account(user_id):
    if current_user.id != int(user_id) and not current_user.has_role('admin'):
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    user = User.query.filter_by(id=user_id).first()
    staff_info = Staff.query.filter_by(id=user.staff_id).first()
    return render_template('my_account.html', user=user, staff=staff_info)


@bp.route("/update_account/<user_id>", methods=['GET', 'POST'])
@login_required
def update_account(user_id):
    form = UpdateForm(request.form)
    user = User.query.filter_by(id=user_id).first()
    staff_info = Staff.query.filter_by(id=user.staff_id).first()
    if current_user.id != int(user_id) and not current_user.has_role('admin'):
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        if form.validate_on_submit():
            user.username = form.username.data
            user.email = form.email.data
            if form.password.data:
                user.password = bcrypt.generate_password_hash(
                    form.password.data).decode('utf-8')
            db.session.commit()
            flash('Account updated successfully.', 'success')
            return redirect(url_for('auth.my_account', user_id=user.id))
    form.username.data = user.username
    form.email.data = user.email
    form.first_name.data = staff_info.first_name
    form.last_name.data = staff_info.last_name
    # form.roles.choices = [(role.id, role.name) for role in Role.query.all()]
    # form.roles.default = [role.id for role in user.roles]
    # form.process()
    return render_template('user_edit.html', form=form, user=user)


@bp.route('/user_list', methods=['GET'])
@login_required
@roles_accepted('admin')
def user_list():
    users = User.query.all()
    return render_template('user_list.html', users=users)
