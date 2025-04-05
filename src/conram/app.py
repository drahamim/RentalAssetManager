import os
from datetime import datetime, timezone
import subprocess

import click
import pandas as pd
from flask import Flask, flash, redirect, render_template, request, url_for, session
from flask_bootstrap import Bootstrap5
from flask_migrate import Migrate
from importlib.metadata import version, PackageNotFoundError
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from flask_moment import Moment
from sqlalchemy import func
from src.conram.auth.auth_routes import my_account
from .models import Asset, Staff, Checkout, History, db, GlobalSet, Role, User
from .forms import SettingsForm, UploadForm

from flask_login import LoginManager, login_required
from flask_security import Security, SQLAlchemyUserDatastore, roles_accepted
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URI', 'sqlite:////tmp/test.db')
bootstrap = Bootstrap5(app)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'os.urandom(24)')
app.config['upload_folder'] = '/tmp/uploads'
moment = Moment(app)
bcrypt = Bcrypt(app)


# Flask Security Setup
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'signin'


@login_manager.user_loader
def load_user(id):
    return User.query.filter_by(fs_uniquifier=id).first()


@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to access this page.', 'warning')
    return redirect(url_for('auth.signin', next=request.endpoint))


if not os.path.exists(app.config['upload_folder']):
    os.makedirs(app.config['upload_folder'])

# Init DB
with app.app_context():
    db.init_app(app)
    db.create_all()
    db.session.commit()
migrate = Migrate(app, db, render_as_batch=True)

# Init Roles
with app.app_context():
    from .auth import auth_routes
    if not db.session.query(Role).filter(Role.name == 'admin').first():
        db.session.add(Role(name='admin', id=1, description='Admin Role'))
        app.logger.info('Admin role created')
    if not db.session.query(Role).filter(Role.name == 'user').first():
        db.session.add(Role(name='user', id=2, description='User Role'))
        app.logger.info('User role created')
    db.session.commit()
    app.logger.info('Roles created')
    app.register_blueprint(auth_routes.bp)
# @app.context
# def inject_settings():
#     if not db.session.query(GlobalSet).filter(GlobalSet.settingid == "timezone"):
#         db.session.add(GlobalSet(settingid="timezone", setting="UTC"))
#         db.session.commit()
#     else:
#         print("timezone already set")
#     return dict(settings=db.session.query(GlobalSet).all())


@app.context_processor
def get_version():
    try:
        version("ConRAM")
    except PackageNotFoundError:
        return dict(app_version=subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True).stdout.decode('utf-8').strip())
    return dict(app_version=version("ConRAM"))

# ASSET ROUTES


from urllib.parse import urlparse

def redirect_dest(fallback):
    dest = request.args.get('next')
    if dest:
        dest = dest.replace('\\', '/')
        parsed_url = urlparse(dest)
        if not parsed_url.netloc and not parsed_url.scheme:
            return redirect(dest)
    return redirect(fallback)


# Register the blueprint


@app.route('/')
def index():
    assets = db.session.query(Asset).all()
    asset_total = db.session.query(Asset).count()
    asset_types = db.session.query(
        Asset.asset_type, db.func.count()).group_by(Asset.asset_type).all()
    asset_status = db.session.query(
        Asset.asset_type,
        db.func.count().label('TotalCount'),
        db.func.sum(db.case(
            (Asset.asset_status == 'checkedout', 1), else_=0)).label(
            'AvailCount')
    ).group_by(Asset.asset_type).all()
    checkouts = db.session.query(Checkout).order_by('timestamp').all()
    demo = db.session.query(GlobalSet).filter(
        GlobalSet.settingid == "demo").first()
    return render_template(
        'index.html', assets=assets, asset_total=asset_total,
        asset_type=asset_types, asset_status=asset_status, checkouts=checkouts, demo=demo)


@app.route('/create/asset', methods=('GET', 'POST'))
@login_required
@roles_accepted('admin')
def asset_create():

    if request.method == 'POST':
        asset_id = request.form['id']
        asset_type = request.form['asset_type']
        asset_status = request.form['asset_status']
        app.logger.info(
            f'Creating asset: {asset_id}, {asset_type}, {asset_status}')
        if not asset_id or not asset_status or not asset_type:
            flash(
                'All fields are required',
                "warning")
        if db.session.query(Asset).filter(
                func.lower(Asset.id) == asset_id.lower()).all():
            flash(
                'Asset already exists',
                "warning")
            return redirect(url_for('asset_create'))
        else:
            try:
                new_asset = Asset(id=asset_id, asset_status=asset_status,
                                  asset_type=asset_type)
                db.session.add(new_asset)
                db.session.commit()
                flash(

                    f'Asset "{asset_id}" was successfully created!', "success")
                return redirect(url_for('assets'))
            except Exception as e:
                app.logger.error(e)
                flash(
                    "Asset creation failed", 'warning')
                return redirect(url_for('asset_create'))

    return render_template('asset_create.html')


@app.route('/edit/asset/<asset_id>', methods=('GET', 'POST'))
def asset_edit(asset_id):
    asset = db.session.query(Asset).filter_by(id=asset_id).first()

    if request.method == 'POST':
        asset_id = asset_id
        asset_type = request.form['asset_type']
        asset_status = request.form['asset_status']

        db.session.query(Asset).filter(Asset.id == asset_id).update(
            values={Asset.asset_status: asset_status,
                    Asset.asset_type: asset_type})
        db.session.commit()
        return redirect(url_for('assets'))

    return render_template('asset_edit.html', asset=asset)


@app.route('/delete/asset/<asset_id>', methods=('POST',))
@login_required
@roles_accepted('admin')
def asset_delete(asset_id):
    db.session.delete(Asset.query.get(asset_id))
    db.session.commit()
    flash(
        f'Asset "{asset_id}" was successfully deleted!', "success")
    return redirect(url_for('assets'))

# STAFF ROUTES


@app.route('/create/staff', methods=('GET', 'POST'))
@login_required
def staff_create():

    if request.method == 'POST':
        staff_id = request.form['staffid']
        first_name = request.form['firstname']
        last_name = request.form['lastname']
        division = request.form['division']
        department = request.form['department']
        title = request.form['title']

        if not staff_id or not first_name:
            flash(
                'All fields are required',
                "warning")

        if db.session.query(Staff).filter(
                func.lower(Staff.id) == staff_id.lower()).all():
            flash(
                'Staff already exists',
                "warning")
            return redirect(url_for('staff_create'))
        else:
            try:
                db.session.add(Staff(id=staff_id, first_name=first_name,
                                     last_name=last_name, division=division,
                                     department=department, title=title))
                db.session.commit()
                return redirect(url_for('staffs'))
            except Exception as e:
                app.logger.error(e)
                flash(
                    "Staff already exists", 'warning')
                return redirect(url_for('staff_create'))

    return render_template('staff_create.html')


@app.route('/staffs')
@login_required
def staffs():
    staff_list = db.session.query(Staff).order_by('id').all()
    for staff in staff_list:
        if db.session.query(User).filter(User.staff_id == staff.id).first():
            staff.is_active = True
        else:
            staff.is_active = False
    return render_template('staff.html', staffs=staff_list)


@app.route('/edit/staff/<staff_id>', methods=('GET', 'POST'))
@login_required
@roles_accepted('admin')
def staff_edit(staff_id):
    staff = db.session.query(Staff).filter_by(id=staff_id).first()
    if request.method == 'POST':
        first_name = request.form['firstname']
        last_name = request.form['lastname']
        division = request.form['division']
        department = request.form['department']
        title = request.form['title']

        db.session.query(Staff).filter(Staff.id == staff_id).update(
            values={Staff.first_name: first_name, Staff.last_name: last_name,
                    Staff.division: division, Staff.department: department,
                    Staff.title: title})
        db.session.commit()
        return redirect(url_for('staffs'))

    return render_template('staff_edit.html', staff=staff)

# Disable Staff Delete function
# @app.route('/delete/staff/<staff_id>', methods=('POST',))
# def staff_delete(staff_id):
#     staffs = Table('staffs', MetaData(bind=engine), autoload=True)
#     db_session.execute(delete(staffs).where(staffs.c.staff_id == staff_id))
#     db_session.commit()
#     flash(
# f'Staff "{staff_id}" was successfully deleted!', "success")
#     return redirect(url_for('staffs'))

# ACTION ROUTES


@app.route('/checkout', methods=('GET', 'POST'))
@login_required
def checkout():

    if request.method == 'POST':
        asset_id = request.form['id']
        staff_id = request.form['staffid']
        accessory_id = request.form['accessoryid']
        if not asset_id or not staff_id:
            flash(
                'Staff and or Asset fields are required',
                "warning")
        if not db.session.query(db.session.query(Asset).filter(
                func.lower(Asset.id) == asset_id.lower()).exists()
        ).scalar():
            flash(
                'Asset does not exist',
                "warning")
            return render_template('checkout.html')
        if not db.session.query(db.session.query(Staff).filter(
                func.lower(Staff.id) == staff_id.lower()).exists()
        ).scalar():
            flash(
                'Staff does not exist',
                "warning")
            return render_template('checkout.html')
        if accessory_id:
            if not db.session.query(db.session.query(Asset).filter(
                    func.lower(Asset.id) == accessory_id.lower()).exists()
            ).scalar() and accessory_id != '':
                flash(
                    'Accessory does not exist',
                    "warning")
                return render_template('checkout.html')
            if db.session.query(Checkout).filter(func.lower(
                    func.lower(Checkout.assetid)
            ) == accessory_id.lower()).first():
                flash(

                    'Accessory already checked out no checkouts saved',
                    "warning")
                return render_template('checkout.html')

        if db.session.query(Checkout).filter(func.lower(
                func.lower(Checkout.assetid)) == asset_id.lower()).first():
            flash(
                'Asset already checked out no checkouts saved',
                "warning")
            return render_template('checkout.html')

        else:
            try:
                staffer = db.session.query(Staff).filter(
                    func.lower(Staff.id) == staff_id.lower()).first()
                asset = db.session.query(Asset).filter(
                    func.lower(Asset.id) == asset_id.lower()).first()
                print('add checkout')
                db.session.add(Checkout(
                    assetid=asset.id, staffid=staffer.id,
                    department=staffer.department,
                    timestamp=datetime.now(timezone.utc)))
                print('update asset')
                db.session.query(Asset).filter(
                    Asset.id == asset.id).update(values={
                        'asset_status': 'checkedout'})

                if accessory_id:
                    print("accessory id found")
                    accessory = db.session.query(Asset).filter(
                        func.lower(Asset.id) == accessory_id.lower()).first()

                    db.session.add(Checkout(
                        assetid=accessory.id, staffid=staffer.id,
                        department=staffer.department,
                        timestamp=datetime.now(timezone.utc)))
                    db.session.query(Asset).filter(func.lower(
                        Asset.id) == accessory_id.lower()).update(values={
                            'asset_status': 'checkedout'})

                db.session.commit()
                flash(
                    'Asset was successfully checked out!', "success")
                return redirect(url_for('checkout'))
            except Exception as e:
                app.logger.error(e)
                flash(
                    "Checkout failed", 'warning')
                return redirect(url_for('checkout'))

    return render_template('checkout.html')


@app.route('/return_asset', methods=('GET', 'POST'))
@login_required
def return_asset():
    if request.method == 'POST':
        asset_id = request.form['id']

        if not asset_id:
            flash(
                'Asset ID is required',
                "warning")
        else:
            try:
                print('get checkout info')
                checkout_info = db.session.query(Checkout).filter(
                    func.lower(Checkout.assetid) == asset_id.lower()
                ).first()
                print('get staffer info')
                staffer = db.session.query(Staff).filter(
                    func.lower(Staff.id) == checkout_info.staffid.lower()
                ).first()

                print('add history')
                db.session.add(History(
                    assetid=checkout_info.assetid,
                    staffid=checkout_info.staffid,
                    department=staffer.department,
                    division=staffer.division,
                    checkouttime=checkout_info.timestamp,
                    returntime=datetime.now(timezone.utc)))
                print('update asset')
                db.session.query(Asset).filter(
                    Asset.id == checkout_info.assetid).update(values={
                        'asset_status': 'Available'})
                print('delete checkout')
                db.session.query(Checkout).filter(
                    Checkout.assetid == checkout_info.assetid).delete()
                print('commit')
                current_checkouts = db.session.query(Checkout).filter(
                    Checkout.staffid == staffer.id).all()
                db.session.commit()
                if not current_checkouts:
                    flash(
                        'Asset was successfully returned!', "success")
                    return redirect(url_for('return_asset'))
                else:
                    assets_still_out = len(current_checkouts)
                    flash(
                        'Asset was successfully returned!', "success")
                    flash(
                        f'Staffer still has {assets_still_out} assets checked out',
                        "warning")
                    return redirect(url_for('return_asset'))
            except Exception as e:
                app.logger.error(e)
                asset_valid = db.session.query(Asset).filter(
                    func.lower(Asset.id) == asset_id.lower()).first()
                if not checkout_info and asset_valid:
                    flash(
                        'Asset not checked out', 'warning')
                    return redirect(url_for('return_asset'))
                elif not checkout_info and not asset_valid:
                    flash(
                        'Asset does not exist', 'warning')
                    return redirect(url_for('return_asset'))
                else:
                    flash(
                        "Return failed", 'warning')
                    return redirect(url_for('return_asset'))
    return render_template('return.html')

# READ ROUTES


@app.route('/history')
@login_required
def history():
    try:
        history_list = db.session.query(History).order_by('returntime').all()
        db.session.commit()
    except Exception as e:
        app.logger.error(e)
        flash(
            "History not found", 'warning')
        return redirect(url_for('history'))
    return render_template('history.html', assets=history_list)


@app.route('/assets')
@login_required
def assets():
    asset_list = Asset.query.all()
    return render_template('status.html', assets=asset_list)


@app.route('/single_history/<rq_type>/<item_id>', methods=['GET'])
@login_required
def single_history(rq_type, item_id):

    if rq_type == 'asset':
        item_info = db.session.query(Asset).get(item_id)
        current = db.session.query(Checkout).filter_by(assetid=item_id).all()
        history = db.session.query(History).order_by(
            'returntime').filter_by(assetid=item_id).all()
    elif rq_type == 'staff':
        item_info = db.session.query(Staff).get(item_id)
        current = db.session.query(Checkout).filter_by(staffid=item_id).all()
        history = db.session.query(History).order_by(
            'returntime').filter_by(staffid=item_id).all()
    return render_template(
        'single_history.html', hist_type=rq_type,
        current=current, history=history, item_info=item_info
    )


# IMPORT TASKS
@app.route('/bulk_import', methods=('GET', 'POST'))
@login_required
@roles_accepted('admin')
def bulk_import():
    form = UploadForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            file = form.file.data
            sec_file_name = secure_filename(file.filename)
            file_path = os.path.join(
                app.config['upload_folder'], sec_file_name)
            file.save(file_path)
            session['uploaded_data_file_path'] = file_path
            app.logger.error(form.data_type.data)
            return redirect(url_for('showData', form_type=form.data_type.data))
        else:
            flash(
                'Invalid file type. Only CSV files are allowed.',
                'danger')

    return render_template('bulk_import.html', form=form)


def parseCSV_assets(filePath, asset_id, asset_type, asset_status):
    csvData = pd.read_csv(filePath, header=0, keep_default_na=False)
    for i, row in csvData.iterrows():
        if asset_status != 'Available':
            asset_status == row[asset_status]

        try:
            asset = Asset(id=str(row[asset_id]).lower(
            ), asset_type=row[asset_type], asset_status=asset_status)
            db.session.add(asset)
            db.session.commit()
        except IntegrityError as e:
            app.logger.error(e)
            flash(

                "Asset upload failed import. This mabe be due to ID conflicts",
                "danger")
            return redirect(url_for('asset_create'))
    return redirect(url_for('assets'))


def parseCSV_staff(
        filePath, first_name=False,
        last_name_col=False, staff_id=False,
        division_col=False, department=False, title_col=False):
    csvData = pd.read_csv(filePath, header=0, keep_default_na=False)
    for i, row in csvData.iterrows():
        try:
            last_name = row[last_name_col] if last_name_col else ""
            division = row[division_col] if division_col else ""
            title = row[title_col] if title_col else ""

            staff = Staff(id=row[staff_id], first_name=row[first_name],
                          last_name=last_name, division=division,
                          department=row[department], title=title)
            db.session.add(staff)
            db.session.commit()
        except IntegrityError:
            flash(

                "Staff upload failed import. This may be due to ID conflicts.",
                "danger")
            return redirect(url_for('staff_create'))
    return redirect(url_for('staffs'))


@app.route('/show_data', methods=["GET", "POST"])
@login_required
def showData():
    # Retrieving uploaded file path from session
    data_file_path = session.get('uploaded_data_file_path', None)
    print("Data_FIle_Path" + data_file_path)
    # read csv file in python flask (reading uploaded csv file from uploaded server location)
    uploaded_df = pd.read_csv(data_file_path)

    # pandas dataframe to html table flask
    uploaded_df_html = uploaded_df.to_html()
    if request.method == "GET":
        headers = pd.read_csv(data_file_path, nrows=1).columns.tolist()
        form_type = request.args.get('form_type')
        return render_template(
            'bulk_import_verify.html', data_var=uploaded_df_html,
            headers_list=headers, form_type=form_type)
    if request.method == "POST":
        form_type = request.args.get('form_type')
        if form_type == 'assets':
            asset_id_field = request.form['asset_id']
            asset_type_field = request.form['asset_type']
            asset_status_field = request.form['asset_status']

            parseCSV_assets(
                data_file_path, asset_id_field,
                asset_type_field, asset_status_field)
            return redirect(url_for('assets'))
        elif form_type == 'staff':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            staff_id = request.form['staff_id']
            division = request.form['division']
            department = request.form['department']
            title = request.form['title']
            parseCSV_staff(
                data_file_path, first_name, last_name, staff_id,
                division, department, title)

            return redirect(url_for('staffs'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
@roles_accepted('admin')
def settings():
    form = SettingsForm()
    if form.validate_on_submit():
        tz = GlobalSet.query.filter_by(settingid="timezone").first()
        tz.setting = form.timezone.data
        db.session.commit()
        flash(
            'Your settings have been updated.')
        return redirect(url_for('settings'))
    elif request.method == 'GET':
        form.timezone.data = db.session.query(GlobalSet).filter(
            GlobalSet.settingid == "timezone").first().setting
    return render_template('settings.html', title='Settings', form=form)


@app.route('/search', methods=["GET", "POST"])
@login_required
def search():
    app.logger.info('Search request')
    query = request.args.get('query')
    app.logger.info
    (f'Search request: {query}')
    query = str(query)
    asset = db.session.query(Asset).filter(
        func.lower(Asset.id).like(f"%{query.lower()}%")).all()
    staff = db.session.query(Staff).filter(
        func.lower(Staff.id).like(f"%{query.lower()}%")).all()
    db.session.commit()
    print(asset)
    print(staff)

    if len(asset) == 1 and len(staff) == 0:
        app.logger.info
        (f'Asset found: {query}')
        return redirect(url_for('single_history',
                                rq_type='asset', item_id=asset[0].id))
    elif len(staff) == 1 and len(asset) == 0:
        app.logger.info
        (f'Staff found: {query}')
        app.logger.info
        (staff[0].id)
        return redirect(url_for('single_history',
                                rq_type='staff', item_id=staff[0].id))
    elif not asset and not staff:
        flash(
            'No results found', 'warning')
        app.logger.info
        ('No results found')
        return redirect(url_for('index'))
    else:
        flash(
            "multiple results found", 'warning')
        app.logger.info
        ('multiple results found')
        app.logger.info
        (len(asset))
        app.logger.info
        (len(staff))
        return render_template('search.html', assets=asset, staff=staff)


@app.cli.command('create-admin')
@click.argument('password')
def create_admin(password):
    """Creates an admin user."""
    with app.app_context():
        user_datastore.create_user(
            username='admin',
            email="admin@",
            active=True,
            staff_id="admin",
            roles=['admin'],
            password=bcrypt.generate_password_hash(password).decode('utf-8'))
        db.session.add(Staff(id='admin', first_name='admin', last_name='',
                             division='', department='', title='admin'))
        db.session.commit()
        app.logger.info('Admin user created')
        print('Admin user created')


@app.cli.command('create-demo')
def create_demo():
    """Creates a demo app with admin/user profiles."""
    with app.app_context():
        app.logger.info('Creating demo users')
        # Set app for demo mode
        db.session.add(GlobalSet(settingid='demo', setting="yes"))
        app.logger.info('Demo mode set')
        for account in ['user', 'admin']:
            user_datastore.create_user(
                username=account,
                email=f"{account}@",
                active=True,
                staff_id=account,
                roles=[account],
                password=bcrypt.generate_password_hash(account).decode('utf-8'))

            db.session.add(Staff(id=account, first_name=account, last_name='',
                                 division='', department='', title=account))

            db.session.commit()
            app.logger.info(f'Demo user {account} created')

        print('Demo users created')
