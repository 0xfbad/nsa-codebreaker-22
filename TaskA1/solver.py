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
	for user, sessions in logons.items():
		for i, session in enumerate(sessions):
			start_time = session["timeBegan"]
			end_time = start_time + session["duration"]

			for next_session in sessions[i + 1:]:
				next_start_time = next_session["timeBegan"]
				next_end_time = next_start_time + next_session["duration"]

				if start_time != next_start_time: # Make sure not comparing the same session
					if next_start_time <= end_time and next_end_time >= start_time: # Check if next session is within the same time period
						print(f'[!] Found multiple concurrent sessions for {user}')
						print(f'[*] Session 1: {datetime.datetime.fromtimestamp(start_time)} EDT - {datetime.datetime.fromtimestamp(end_time)} EDT, duration of {format(session["duration"]/3600, ".2f")} hours')
						print(f'[*] Session 2: {datetime.datetime.fromtimestamp(next_start_time)} EDT - {datetime.datetime.fromtimestamp(next_end_time)} EDT, duration of {format(next_session["duration"]/3600, ".2f")} hours')
						print(f'[?] IPs: {session["ip"]} and {next_session["ip"]}')
						return

if __name__ == "__main__":
	scan()