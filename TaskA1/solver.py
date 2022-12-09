import datetime

# All connections
logons = {}

def logon(name, timeBegan, duration, ip):
	if name in logons:
		logons[name].append({"timeBegan": timeBegan, "duration": duration, "ip": ip})
	else:
		logons[name] = [{"timeBegan": timeBegan, "duration": duration,"ip": ip}]

# Populate logons with data from log file
with open("./provided/vpn.log", "r") as log:
	for line in log:
		# Skip first line and all lines with errors
		if "Error" in line or "user not found" in line or "invalid credential" in line:
			continue

		line = line.split(",")

		startTime = datetime.datetime.strptime(line[2], "%Y.%m.%d %H:%M:%S EDT")
		logon(line[1], startTime.timestamp(), int(line[3]), line[7])

# Find if any user has multiple sessions at the same time
def scan():
	for user in logons:
		if len(logons[user]) > 1: # no need to check users with only one session
			for session in logons[user]:
				startTime = session["timeBegan"]
				endTime = startTime + session["duration"]

				# Check if next session is within the same time period
				for nextSession in logons[user]:
					nextStartTime = nextSession["timeBegan"]
					nextEndTime = nextStartTime + nextSession["duration"]

					if startTime != nextStartTime: # Make sure not comparing the same session
						if nextStartTime <= endTime and nextEndTime >= startTime: # Check if next session is within the same time period
							print(f'[!] Found multiple concurrent sessions for {user}')
							print(f'[*] Session 1: {datetime.datetime.fromtimestamp(startTime)} EDT - {datetime.datetime.fromtimestamp(endTime)} EDT, duration of {format(session["duration"]/3600, ".2f")} hours')
							print(f'[*] Session 2: {datetime.datetime.fromtimestamp(nextStartTime)} EDT - {datetime.datetime.fromtimestamp(nextEndTime)} EDT, duration of {format(nextSession["duration"]/3600, ".2f")} hours')
							print(f'[?] IPs: {session["ip"]} and {nextSession["ip"]}')
							return

if __name__ == "__main__":
	scan()