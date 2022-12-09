<!-- HEADER -->
<div align="center">

# [\[<<\]](../Task7/) Task 8 - Raiding the Vault [\[>>\]](../Task9/)
![Category: Reverse Engineering, [redacted]](https://img.shields.io/badge/Category-Reverse_Engineering,_[redacted]-informational?style=flat-square)
![Points: 2000](https://img.shields.io/badge/Points-2000-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/odFeEOF.png)

</div>

<!-- DESCRIPTION -->
> You're an administrator! Congratulations!
> 
> It still doesn't look like we're able to find the key to recover the victim's files, though. Time to look at how the site stores the keys used to encrypt victim's files. You'll find that their database uses a "key-encrypting-key" to protect the keys that encrypt the victim files. Investigate the site and recover the key-encrypting key.
> 
> ---
> 
> Enter the base64-encoded value of the key-encrypting-key
> ```
> ```

## Files
* [provided/](provided/)
	- (empty)
* [keygeneration.log](keygeneration.log)
* [keyMaster.log](keyMaster.log)
* [victims.db](victims.db)
* [user.db](user.db)
* [keyMaster.db](keyMaster.db)

<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution
So we got access to the admin page! Lets take a look:

![Admin Page](https://i.imgur.com/jyBWlrY.png)

Clicking on `Retrieve List`, we get a [key generation log](keygeneration.log). Hm, lets look into that function in [app/sever.py](../TaskB2/repo/app/server.py):

```py
def fetchlog():
	log = request.args.get('log')
	return send_file("/opt/ransommethis/log/" + log)
```

And lets check what the [admin.html](../TaskB2/repo/app/templates/admin.html) page looks like:

```html
  <div class="column">
    <div class="box">
 	<h3 style="text-align:center;">Key Generation Log </h3>
        <p> Access the key generation log, for troubleshooting purposes. </p>
	<button type="button" onclick="window.location.href = 'fetchlog?log=keygeneration.log'"> Retrieve List </button>
  </div>
  </div>
```

So seems like its going to `fetchlog?log=keygeneration.log`, lets check if we can do a path traversal exploit by going to root using `fetchlog?log=../..`:

![Fetchlog](https://i.imgur.com/1j2YAUU.png)

Awesome, so lets see what we can get. Looking into into the [app/sever.py](../TaskB2/repo/app/server.py) code more, we can see multiple references to a file called `keyMaster`:

```py
def lock():
# (snipped)
	result = subprocess.run(["/opt/keyMaster/keyMaster", 
								'lock',
								str(cid),
								request.args.get('demand'),
								util.get_username()],
								capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
# (snipped)

def unlock():
# (snipped)
	result = subprocess.run(["/opt/keyMaster/keyMaster", 
								'unlock', 
								request.args.get('receipt')],
							capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
# (snipped)

def credit():
# (snipped)
	result = subprocess.run(["/opt/keyMaster/keyMaster", 
							'credit',
							args.get('hackername'),
							args.get('credits'),
							args.get('receipt')],
							capture_output=True, check=True, text=True, cwd="/opt/keyMaster")
# (snipped)
```

So how do we get `keyMaster`, well, since we know that `fetchlog?log=../..` is opt, we can go to `fetchlog?log=../../keyMaster/keyMaster`:

![Fetchlog](https://i.imgur.com/m2sIS6M.png)

And we got [keyMaster](keyMaster), nice. Looking into [app/util.py](../TaskB2/repo/app/util.py) we can see those sql databases we interacted with earlier:

```py
@contextmanager 
def victimdb():
	victimdb = "/opt/ransommethis/db/victims.db"
	try:
		con = sqlite3.connect(victimdb)
		yield con
	finally:
		con.close()

@contextmanager
def userdb():
	userdb = f"/opt/ransommethis/db/user.db"
	try:
		con = sqlite3.connect(userdb)
		yield con
	finally:
		con.close()
```

Lets download those by going to `fetchlog?log=../../ransommethis/db/victims.db` and `fetchlog?log=../../ransommethis/db/user.db`:

![Fetchlog](https://i.imgur.com/uQ4JBFQ.png)

We'll keep [victims.db](victims.db) and [user.db](user.db) just in case we need them later in our investigation. Now lets take a look at how the site stores the keys used to encrypt victim's files. We can see there's a `lock` function in [app/server.py](../TaskB2/repo/app/server.py):

```py
def lock():
	if request.args.get('demand') == None:
		return render_template('lock.html')
	else:
		cid = random.randrange(10000, 100000)
		result = subprocess.run(["/opt/keyMaster/keyMaster", 
								 'lock',
								 str(cid),
								 request.args.get('demand'),
								 util.get_username()],
								 capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
		jsonresult = json.loads(result.stdout)
		if 'error' in jsonresult:
			response = make_response(result.stdout)
			response.mimetype = 'application/json'
			return response
		
		with open("/opt/ransommethis/log/keygeneration.log", 'a') as logfile:
			print(f"{datetime.now().replace(tzinfo=None, microsecond=0).isoformat()}\t{util.get_username()}\t{cid}\t{request.args.get('demand')}", file=logfile)
		return jsonify({'key': jsonresult['plainKey'], 'cid': cid})
```

From here, we can see there are 4 parameters, `lock` the action to be performed, `cid` the unique id of the key (in [task B1](../TaskB1/), we know our victims cid was `92807`), `demand` the amount the victim needs to pay, and `username` the username of the hacker. But first lets see what `keyMaster` is:

```
$ file keyMaster
keyMaster: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, Go BuildID=FeeM7E1BxG8P8Nja2FeT/6JtOtF_3gBRqjJolw_C5/9-c3gRqihLNGfuGBnA4q/VjnaYGjdxFpj1FM_kEnN, BuildID[sha1]=64c92e0c1609beaae73cb04c698f3ecbf5b1b35b, stripped
```

Lets run the binary in a sandbox with the known arguments for our victim:

```
$ ./keyMaster lock 1 1 0xfbad
{"error":"no such table: hackers"}
```

I noticed after doing this, a `keyMaster.db` file was created in the same directory. Which means there's a file that this binary references, lets download the [database](keyMaster.db) in case we need it later by going to `fetchlog?log=../../keyMaster/keyMaster.db`. As the site said, this is a months old key database:

![Site Home Page](https://i.imgur.com/grK4cJO.png)

Anyway, lets look into the code of the binary by opening it in Ghidra. And since it's a Go binary, its a real mess:

![Ghidra](https://i.imgur.com/tQKuRIK.png)

Disassembling Go is known to be a pain due to its compiler optimizations. But luckily for us, people have had the same issue and they have made tools to help us. I suggest reading [CUJO AI's blog post](https://cujo.com/reverse-engineering-go-binaries-with-ghidra/) on reversing Go binaries. But anyway, we'll be using their Ghidra scripts, which can be found [here](https://github.com/getCUJO/ThreatIntel/tree/master/Scripts/Ghidra). Let's load those scripts up in Ghidra:

![Ghidra Scripts](https://i.imgur.com/TB756Q6.png)

Now, we should be able to go to `main.main` and see the actual main function:

![Ghidra Main](https://i.imgur.com/i51dwoh.png)

Looks much better! Lets take a look around. We can actually see right away where its comparing if a given argument is `unlock` (its reversed due to endianness):

![Ghidra Unlock](https://i.imgur.com/46mbE1R.png)

Lets browse for the unlock function:

![Ghidra Unlock Function](https://i.imgur.com/RZ8qpRF.png)

I stumbled across this function while browsing, and it looks interesting:

![Ghidra Unlock Function](https://i.imgur.com/dgLFzJZ.png)

Interesting, looking inside, we notice that the decompilation lacks a bit (which is probably due to Ghidra's dead code detection), but we can also see a call to `crypto/aes.NewCipher`:

![Ghidra Unlock Function](https://i.imgur.com/ac77rzv.png)

Let's see what that call before it is. It looks like its generating a PBDKF2 key! That must be what they're encrypting the keys with via AES. *If you're wondering why theres such a big block of text, its because Go binaries don't have string terminations so you get large blocks of text like this*:

![Ghidra Unlock Function](https://i.imgur.com/CxF9B99.png)

Well lets not waste any time, lets go back and look at the address of the `crypto/aes.NewCipher` call:

![Ghidra Unlock Function](https://i.imgur.com/YmZrzX4.png)

Ok so its being called at `0x005b87d5`, since the PBKDF2 return is right above it, it will probably be stored on the first register, `RAX`. Lets set a breakpoint there and see what happens:

Lets open up gdb and set a breakpoint at that address:

```
$ gdb -q keyMaster
Reading symbols from keyMaster...
(No debugging symbols found in keyMaster)

(gdb) b *0x005b87d5
Breakpoint 1 at 0x5b87d5
```

Now lets run it with arguments so it gets to the breakpoint in the lock section:

```
(gdb) run lock 1 1 0xfbad
Starting program: /.../keyMaster lock 1 1 0xfbad
(...)
Thread 1 "keyMaster" hit Breakpoint 1, 0x00000000005b87d5 in ?? ()
```

And now we can check `RAX` to see what that PBDKF2 key is:
```
(gdb) info registers
rax            0xc000148100        824635064576
rbx            0x20                32
rcx            0x20                32
rdx            0x20                32
rsi            0x0                 0
rdi            0x0                 0
(...)

(gdb) x/32xb 0xc000148100
0xc000148100:   0x2e    0xe0    0x42    0x12    0xae    0xc5    0x37    0xb9
0xc000148108:   0x51    0xf4    0xd1    0x11    0x00    0x3e    0xd0    0xf7
0xc000148110:   0x87    0xd7    0xaf    0x58    0x22    0x1b    0x92    0x87
0xc000148118:   0x08    0xf0    0x9a    0xa0    0xd3    0x7a    0xb3    0x33
```

So the hex value of key was `0x2e0xe00x420x120xae0xc50x370xb90x510xf40xd10x110x000x3e0xd00xf70x870xd70xaf0x580x220x1b0x920x870x080xf00x9a0xa00xd30x7a0xb30x33`. Lets convert that into base64:

```
$ xxd -r -p <<< "0x2e0xe00x420x120xae0xc50x370xb90x510xf40xd10x110x000x3e0xd00xf70x870xd70xaf0x580x220x1b0x920x870x080xf00x9a0xa00xd30x7a0xb30x33" | base64
LuBCEq7FN7lR9NERAD7Q94fXr1giG5KHCPCaoNN6szM=
```

And we got the base64 represented key! We can submit `LuBCEq7FN7lR9NERAD7Q94fXr1giG5KHCPCaoNN6szM=`:

![Task Screenshot](https://i.imgur.com/eNBhpay.png)

> ```
> Great job! I think we've almost got their files back.
> ```

<!-- TL;DR -->
## Technical TL;DR
Use a path traversal vulnerability to get the keyMaster binary. Then load into Ghidra, find where the PBKDF2 key is generated and returned, then simply catch its return by checking the RAX register when its passed into a function. Convert the hex value to base64 and submit it.

---

<div align="center">

[return to top](#top)

</div>