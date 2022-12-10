<!-- HEADER -->
<div align="center">

# [<<] Task A1 - Initial access [\[>>\]](../TaskA2/)
![Category: Log analysis](https://img.shields.io/badge/Category-Log_analysis-informational?style=flat-square)
![Points: 10](https://img.shields.io/badge/Points-10-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/3TvlTOy.png)

</div>

<!-- DESCRIPTION -->
> We believe that the attacker may have gained access to the victim's network by phishing a legitimate users credentials and connecting over the company's VPN. The FBI has obtained a copy of the company's VPN server log for the week in which the attack took place. Do any of the user accounts show unusual behavior which might indicate their credentials have been compromised?
Note that all IP addresses have been anonymized.
> 
> ---
> 
> Enter the username which shows signs of a possible compromise.
> ```
> ```

## Files
* [provided/](provided/)
	- [vpn.log](provided/vpn.log) - Access log from the company's VPN server for the week in question.
* [solver.py](solver.py) - Python script that automatically analyses the log for concurrent sessions.

<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution

So we're given a log of the company's VPN server. We need to find the user account that is most likely to be compromised. Now think, what is suspicious about the user account? Maybe short duration of connection, or unusual behaviour? Maybe, but connecting quickly and then disconnecting is not that suspicious. How about odd hours of the day? Not really, people can be active at any time of the day. How about multiple connections at the same time? Yeah, that's suspicious.

So lets make a small python script that looks for multiple concurrent sessions. The script will enter all necessary data into a dictionary, then go through each user and see if they have multiple concurrent sessions. 

Dissecting the [script](solver.py), here is the most important part:
```py
for user in logons:
	for user, sessions in logons.items():
		for i, session in enumerate(sessions):
			start_time = session["timeBegan"]
			end_time = start_time + session["duration"]

			for next_session in sessions[i + 1:]:
				next_start_time = next_session["timeBegan"]
				next_end_time = next_start_time + next_session["duration"]

				if start_time != next_start_time: # Make sure not comparing the same session
					if next_start_time <= end_time and next_end_time >= start_time: # Check if next session is within the same time period
						# Found a concurrent session!!
```

See, we're not given an end time, but we are given a duration and a start time. Which means we can get `endTime` by adding the duration to the start time *(small note, I did convert the times from the log to unix time, so the times are all in seconds)*.

Now that we know when each session ends, we can just double loop for each user and check if they have sessions that start before any other sessions end. That's the solution. Let's run the script and see if we get any results.

```
$ python solver.py 
[!] Found multiple concurrent sessions for Donald.Y
[*] Session 1: 2022-03-22 08:32:35 EDT - 2022-03-22 14:15:25 EDT, duration of 5.71 hours
[*] Session 2: 2022-03-22 10:07:18 EDT - 2022-03-22 13:28:14 EDT, duration of 3.35 hours
[?] IPs: 172.29.133.40 and 172.19.3.161
```

Yep, looks like `Donald.Y` has two concurrent sessions, one starting at 8 AM and ending at 2 PM, the other starting at 10 AM and ending at 1 PM. Additionally, the two sessions have different IP addresses, which leads to the suspicion that someone else logged in a different location. While this is not proof of anything, it is something that should be investigated.

Let's submit `Donald.Y`.

![Task Screenshot](https://i.imgur.com/Gch59xt.png)

Looks like we were correct!

> ```
> Nicely done! That user had two simultaneous sessions from different IP addresses. Not proof of anything, but suspicious...
> ```

<!-- TL;DR -->
## Technical TL;DR
Find the user account that has multiple concurrent sessions. While not 100% proof of anything, it is suspicious, especially if the sessions have different IP addresses.

---

<div align="center">

[return to top](#top)

</div>