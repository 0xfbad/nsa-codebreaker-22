<!-- HEADER -->
<div align="center">

# [\[<<\]](../TaskA2/) Task B1 - Information Gathering [\[>>\]](../TaskB2/)
![Category: Reverse Engineering, Web Analysis](https://img.shields.io/badge/Category-Reverse_Engineering,_Web_Analysis-informational?style=flat-square)
![Points: 10](https://img.shields.io/badge/Points-10-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/JkSvfia.png)

</div>

<!-- DESCRIPTION -->
> The attacker left a file with a ransom demand, which points to a site where they're demanding payment to release the victim's files.
> 
> We suspect that the attacker may not have been acting entirely on their own. There may be a connection between the attacker and a larger ransomware-as-a-service ring.
> 
> Analyze the demand site, and see if you can find a connection to another ransomware-related site.
> 
> ---
> 
> Enter the domain name of the associated site.
> ```
> ```

## Files
* [provided/](provided/)
	- [YOUR_FILES_ARE_SAFE.txt](provided/YOUR_FILES_ARE_SAFE.txt) - Demand note from the attacker

<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution

Hmm, looking at the [demand note](provided/YOUR_FILES_ARE_SAFE.txt), we can see a site, lets go to it.

![Website](https://i.imgur.com/aqvN9Md.png)

Not much here, lets check the network traffic and reload the site:

![Website](https://i.imgur.com/b6afseL.pngg)

Interesting, so it downloads a file called `connect.js` then that JavaScript file calls GET to another site called `https://xsafjadfhngjqmit.ransommethis.net/demand?cid=92807`, that must be the other ransomware-related site. We can also see a parameter called `CID` with the value `92807`, lets keep that in the back of our head for later.

*Note: I actually saw some people do this in the CBC Discord, but it's pretty unnecessary, which was to go after the source of the site, so I'll quickly go over how you could do that for whatever reason you'd want to do that.*

Lets take a peek at the source code:

![Website](https://i.imgur.com/qbJJMxf.png)

Horrifying. Its obfuscated, lets run it through an [online deobfuscator such as synchrony](https://deobfuscate.relative.im/). It deobfuscates it pretty fast and we get this:

![Website](https://i.imgur.com/qt0J8I2.png)

Yeah looks like it's intentional, lets submit `xsafjadfhngjqmit.ransommethis.net`.

![Task Screenshot](https://i.imgur.com/lefV5oV.png)

Nice, we got the domain.

> ```
> Nicely done! Looks like there is an association with another site.
> ```

<!-- TL;DR -->
## Technical TL;DR
Use web dev tools to see network traffic when you load the site to see the external request to the other site.

---

<div align="center">

[return to top](#top)

</div>