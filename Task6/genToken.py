import jwt
from datetime import datetime, timedelta


def hmac_key():
	return "xveZHYpG5qqmQeFCezjtof4ZrjCUab7l"

def validate_token(token):
	try:
		return jwt.decode(token, hmac_key(), algorithms=['HS256'])
	except Exception as e:
		return e

def generate_token():
	now = datetime.now()
	exp = now + timedelta(days=365) # so we dont have to worry about it expiring
	claims = {
				'iat': now,
				'exp': exp,
				'uid': 28504, # uid from the token we decoded
				'sec': "YDGl9Or6CP22ddA7cQ9AY015S3Qnnqms" # secret from the token we decoded
			}
	return jwt.encode(claims, hmac_key(), algorithm='HS256')


if __name__ == "__main__":
	token = generate_token()
	print(validate_token(token))
	print(token)