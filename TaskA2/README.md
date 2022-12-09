<!-- HEADER -->
<div align="center">

# [\[<<\]](../TaskA1/) Task A2 - Identifying the attacker [\[>>\]](../TaskB1/)
![Category: Computer Forensics, Packet Analysis](https://img.shields.io/badge/Category-Computer_Forensics,_Packet_Analysis-informational?style=flat-square)
![Points: 40](https://img.shields.io/badge/Points-40-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/LARMWNi.png)

</div>

<!-- DESCRIPTION -->
> Using the timestamp and IP address information from the VPN log, the FBI was able to identify a virtual server that the attacker used for staging their attack. They were able to obtain a warrant to search the server, but key files used in the attack were deleted.
> 
> Luckily, the company uses an intrusion detection system which stores packet logs. They were able to find an SSL session going to the staging server, and believe it may have been the attacker transferring over their tools.
> 
> The FBI hopes that these tools may provide a clue to the attacker's identity
> 
> ---
> 
> What was the username of the account the attacker used when they built their tools?
> ```
> ```

## Files
* [provided/](provided/)
	- [root/](provided/root/) - Files captured from root's home directory on the staging server *(extracted from root.tar.bz2)* - *(root/.local and root/.cache removed)*
		- [.cert.pem](provided/root/.cert.pem) - Certificate for the SSL session
	- [session.pcap](provided/session.pcap) - PCAP file believed to be of the attacker downloading their tools
* [tools/](./tools/) - The tools the attackers transferred.

<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution

So we're given some files off the attackers machine, there we can find [.cert.pem](provided/root/.cert.pem) which we can use to decrypt the SSL session. Lets open [session.pcap](provided/session.pcap) and see what we can find.

![session.pcap](https://i.imgur.com/tuWK5yf.png)

Yep, TLS traffic. Lets add our certificate by going to `Edit -> Preferences -> RSA Keys -> Add New Keyfile` and add the certificate.

![session.pcap](https://i.imgur.com/SIQ9gns.png)

Lets save it by pressing "OK" then pressing CTRL + R to refresh the PCAP. Now we can see the decrypted traffic.

![session.pcap](https://i.imgur.com/wMsnDfL.png)

We can see a GET request to a file called `tools.tar`, lets follow the TLS stream:

![session.pcap](https://i.imgur.com/narvUKF.png)

Interesting! We saw this reference in the [bash_history](./provided/root/.bash_history) file found on the attackers machine:
```sh
cd /root
ls -al
bunzip2 tools.tar.bz2
tar xvf tools.tar
ls
./runwww.py 443
shred -uz tools/* tools.tar
rmdir tools
ls
exit
```

Let's download and see if there's anything interesting in there. Now stay with me here, it's a bit of hacky way to do it, but it works.

First we're going to only select the incoming conversation, which is obviously bigger:

![Wireshark](https://i.imgur.com/iONFVWB.png)

Then let's change it to `Raw` so we only get the raw data:

![Wireshark](https://i.imgur.com/FDTuE2Y.png)

Now lets save it as `tools.tar`:

![Saving the data](https://i.imgur.com/oGMMek4.png)

A weird thing about Wireshark is that it tends to add a header onto the raw data, so lets open up vim and remove it. Now a small note, when I originally did this, I used VS Code's hex editor to do this and it messed up pretty bad, I only got half of the files, so be weary of that.

```
$ head tools -n 4
HTTP/1.0 200 ok
Content-type: text/plain

tools/0000775207042420704240000000000000000000000014243 5ustar  WiryBlackWorkWiryBlackWorktools/busybox0000775207042420704240000767373000000000000015713 0ustar  WiryBlackWorkWiryBlackWork
```

So lets run run `vim tools` and press `i` to enter edit mode:

![Vim](https://i.imgur.com/ICT4eBS.png)

Not lets those first 3 lines, press escape, then type `:wq` to save and quit:

![Vim](https://i.imgur.com/Nmaf365.png)

Now lets take a peak inside, I know you can go about this in different ways but I prefer using 7-zip for the graphical interface. We can see that there's a folder inside called `tools/` and that there are a few files in there! We can also see who owns the files, which is `WiryBlackWork`:

![7-zip](https://i.imgur.com/mYt76Hh.png)

Lets save these to [tools/](./tools/) in case we need them later. We can also submit `WiryBlackWork` as the answer to the task.

![Task Screenshot](https://i.imgur.com/ahFNdpX.png)

We were right!

> ```
> Nicely done! That's a handle the FBI is familiar with.
> ```

<!-- TL;DR -->
## Technical TL;DR
Open given PCAP in Wireshark, add the provided certificate found on the attackers computer and decrypt the traffic. Then follow the TLS traffic and extract the `tools.tar` file. Open the file in a hex editor and remove the header, then extract the files and submit the username of the owner of the files.

---

<div align="center">

[return to top](#top)

</div>