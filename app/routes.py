from flask import render_template, flash, redirect, url_for, request
from app import app, db
from app.forms import LoginForm, RegistrationForm, EditorIp
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User
from werkzeug.urls import url_parse
import netifaces as ni
import subprocess
import pexpect


@app.route('/index')
@app.route('/')
def index():
	return render_template('index.html', title='Home')
		

@app.route('/login', methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('admin'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is None or not user.check_password(form.password.data):
			flash('Invalid username or password')
			return redirect(url_for('login'))
		login_user(user, remember=form.remember_me.data)
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':
			next_page = url_for('admin')
			return redirect(next_page)
		return redirect(url_for('admin'))
	return render_template('login.html', title='Sign In', form=form)


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
	interfaces = []
	all_interfaces = ni.interfaces()
	for interface in all_interfaces:
		addrs = ni.ifaddresses(interface)
		if addrs and addrs.get(ni.AF_INET):
			interfaces.append([interface, addrs[ni.AF_INET]])
	name_interface = [(inter[0], inter[0]) for inter in interfaces]
	form = EditorIp(request.form)
	form.name_inter.choices = name_interface
	if form.validate_on_submit():
		child = pexpect.spawn('sudo',['ifconfig', form.name_inter.data, 
			'inet', form.new_addr.data, 'netmask', form.mask.data])
		child.expect('Password:')
		child.sendline(form.password.data)
		return redirect(url_for('admin'))
	return render_template('admin.html', title='Admin panel', interfaces=interfaces, form=form)


@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('admin'))
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(username=form.username.data)
		user.set_password(form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('Well done')
		return redirect(url_for('login'))
	return render_template('reg.html', title='Register', form=form)




