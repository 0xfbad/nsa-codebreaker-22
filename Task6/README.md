<!-- HEADER -->
<div align="center">

# [\[<<\]](../Task5/) Task 6 - Gaining Access [\[>>\]](../Task7/)
![Category: Web Hacking, [redacted]](https://img.shields.io/badge/Category-Web_Hacking,_[redacted]-informational?style=flat-square)
![Points: 150](https://img.shields.io/badge/Points-150-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/udBJCYq.png)

</div>

<!-- DESCRIPTION -->
> We've found the login page on the ransomware site, but we don't know anyone's username or password. Luckily, the file you recovered from the attacker's computer looks like it could be helpful.
> 
> Generate a new token value which will allow you to access the ransomware site.
> 
> ---
> 
> Enter a token value which will authenticate you as a user of the site.
> ```
> ```

## Files
* [provided/](provided/)
	- (empty)
* [genToken.py](genToken.py) - Generates a new token.

<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution
In the last task we got a [Netscape HTTP cookie file](../Task5/data.txt) from the attacker's computer. Using the [server source](../TaskB2/repo/) we can reverse a way to generate a new token. Lets start by looking at [repo/app/util.py](../TaskB2/repo/app/util.py):

So what we need to target is this function:

```py
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
```

Okay, so we don't have access to the user database, but we do have access to the old token. With this, we can simply decode it (as its encoded in base64 or we can use [a jwt decoder](https://jwt-decoder.com/) to make it pretty) and see the main values of the token. Decoding the token, we get:

![Decoded Token](https://i.imgur.com/13SVfzO.png)

```json
{
  "typ": "JWT",
  "alg": "HS256"
}

{
  "iat": 1653336792,
  "exp": 1655928792,
  "sec": "YDGl9Or6CP22ddA7cQ9AY015S3Qnnqms",
  "uid": 28504
}
```

Since we have the HMAC key from the server, which is used to sign the token, we can simply generate a new token with the same values. We can reverse the `generate_token` function to get the values we need to generate a new token. Additionally, we can se the expiration date to a year, so we don't have to worry about it expiring.

So lets manually copy the `sec` and `uid` values to our [python script](genToken.py) and run the generation tool:

```
$ python genToken.py
{'iat': 1670586517, 'exp': 1702122517, 'uid': 28504, 'sec': 'YDGl9Or6CP22ddA7cQ9AY015S3Qnnqms'}
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzA1ODY1MTcsImV4cCI6MTcwMjEyMjUxNywidWlkIjoyODUwNCwic2VjIjoiWURHbDlPcjZDUDIyZGRBN2NROUFZMDE1UzNRbm5xbXMifQ.MSGaHtEjZ4CltPTRcGeq3TQi1E_HOWPoEoAyyrrg3n8
```

We got a working token with a new expiration date! Lets submit `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzA1ODY1MTcsImV4cCI6MTcwMjEyMjUxNywidWlkIjoyODUwNCwic2VjIjoiWURHbDlPcjZDUDIyZGRBN2NROUFZMDE1UzNRbm5xbXMifQ.MSGaHtEjZ4CltPTRcGeq3TQi1E_HOWPoEoAyyrrg3n8` and continue looking at the site.

![Task Screenshot](https://i.imgur.com/aULzofW.png)

> ```
> Great job! Let's see what else we can discover about the site.
> ```

<!-- TL;DR -->
## Technical TL;DR
Since we have the server source code, we know the JWT token HMAC key, which means we can generate our own key by decoding the old key and then resigning it with the new expiration date.

---

<div align="center">

[return to top](#top)

</div>