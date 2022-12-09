<!-- HEADER -->
<div align="center">

# [\[<<\]](../TaskB2/) Task 5 - Core Dumped [\[>>\]](../Task6/)
![Category: Reverse Engineering, Cryptography](https://img.shields.io/badge/Category-Reverse_Engineering,_Cryptography-informational?style=flat-square)
![Points: 500](https://img.shields.io/badge/Points-500-43853D?style=flat-square)

![Task Screenshot](https://i.imgur.com/o7HlMXy.png)

</div>

<!-- DESCRIPTION -->
> The FBI knew who that was, and got a warrant to seize their laptop. It looks like they had an encrypted file, which may be of use to your investigation.
> 
> We believe that the attacker may have been clever and used the same RSA key that they use for SSH to encrypt the file. We asked the FBI to take a core dump of `ssh-agent` that was running on the attacker's computer.
> 
> Extract the attacker's private key from the core dump, and use it to decrypt the file.
> 
> *Hint: if you have the private key in PEM format, you should be able to decrypt the file with the command `openssl pkeyutl -decrypt -inkey privatekey.pem -in data.enc`*
> 
> ---
> 
> Enter the token value extracted from the decrypted file.
> ```
> ```

## Files
* [provided/](provided/)
	- [core](provided/core) - Core dump of ssh-agent from the attacker's computer
	- [ssh-agent](provided/ssh-agent) - ssh-agent binary from the attacker's computer. The computer was running Ubuntu 20.04.
	- [data.enc](provided/data.enc) - Encrypted data file from the attacker's computer
* [privatekey.pem](privatekey.pem) - Private key extracted from the core dump
* [data.txt](data.txt) - Decrypted data file
	
<!-- BREAKDOWN & SOLUTION -->
## Breakdown & Solution
So we're given to main files [ssh-agent](provided/ssh-agent), the binary that was running, and [core](provided/core), a core dump of [ssh-agent](provided/ssh-agent).

What we need to do is understand the structure of [ssh-agent](provided/ssh-agent). If we know how ssh-agent is structured, then we should be able to know where the private key is located within the core dump.

To start, we need to understand the structure of [ssh-agent](provided/ssh-agent). Looking online, you can find the structure of [ssh-agent.c](https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c) online:

```c
typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
	char *sk_provider;
	struct dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
struct idtable *idtab;
```

Ok, so we need to find `*idtab` first. Then from there we can get the `identity` struct, then from there get `*key`, and finally we can get `*shielded_private`.

First off, we need to find `*idtab`, to do that we need to find that area in memory, to do this we can look back at [ssh-agent.c](https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c) online. See how `socket_name` is a bit below it:

```c
/* private key table */
struct idtable *idtab;

int max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX];
```

Well to find `socket_name` we can just take a look at the code again, I found a [section which has a reference to it](https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c#L2154):

```c
snprintf(socket_name, sizeof socket_name, "%s/agent.%ld", socket_dir, (long)parent_pid);
```

Lets search for all instances of `/agent.` in [core](./provided/core) in a hex editor, in this case I used [HxD](https://mh-nexus.de/en/hxd/):

![Hex View](https://i.imgur.com/xAIOLAd.png)

Result:

![Hex View](https://i.imgur.com/ykUyT7q.png)

Lets highlight the entire section:

![Hex View](https://i.imgur.com/PothI8X.png)

We found `/tmp/ssh-Msw9Q2A5oiIs/agent.18` at offset `0x8e78`. Lets work our way up.

We know where `socket_name` is, that must mean that `*idtab` is above, which can be seen here:

![Hex View](https://i.imgur.com/3tgbVMB.png)

The address there is `0x55e9d0c5a3c0` (from `55 e9 d0 c5 a3 c0`) (notice how its backwards from the hex editor view):

```c
struct idtable *idtab; // pointer to 0x55e9d0c5a3c0

...

char socket_name[PATH_MAX]; // at offset 0x8e78
```

Ok so that's the `idtable` struct pointer. Here's the struct again:

```c
struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};
```

So we can see that the `idtable` struct would contain a single zero integer, a null pointer to `tqh_first` from [sys-queue.h](https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/openbsd-compat/sys-queue.h#L502):

```c
#define TAILQ_HEAD(name, type)
struct name {
	struct type *tqh_first;	/* first element */
	struct type **tqh_last;	/* addr of last next element */
}
```

So lets find it, we can load it up in gdb:

```
$ gdb -q ssh-agent core
(gdb) x/6xg 0x55e9d0c5a3c0
0x55e9d0c5a3c0: 0x0000000000000001      0x000055e9d0c5fb90
0x55e9d0c5a3d0: 0x000055e9d0c5fb90      0x00000000000001e1
0x55e9d0c5a3e0: 0x0000000000000000      0x000055e9d0c3e010
```

The `0x55e9d0c5fb90` is the pointer to the `identity` struct judging from the `idtable` struct we saw from source code. Lets check it:

```
(gdb) x/4xg 0x55e9d0c5fb90
0x55e9d0c5fb90: 0x0000000000000000      0x000055e9d0c5a3c8
0x55e9d0c5fba0: 0x000055e9d0c5dee0      0x000055e9d0c5bc00
```

If this is the `identity` struct, then the 4th pointer should be `*comment`, which is a string, lets check:

```
(gdb) x/s 0x55e9d0c5bc00
0x55e9d0c5bc00: "rUbKfy1noZp6wgMUneTrg"
```

Looks good, which means the 3rd pointer should be `*key`, making `*key` pointing to `0x55e9d0c5dee0`. Lets check it:

```
(gdb) x/22xg 0x55e9d0c5dee0
0x55e9d0c5dee0: 0x0000000000000000      0x000055e9d0c610e0
0x55e9d0c5def0: 0x0000000000000000      0x00000000ffffffff
0x55e9d0c5df00: 0x0000000000000000      0x0000000000000000
0x55e9d0c5df10: 0x0000000000000000      0x0000000000000000
0x55e9d0c5df20: 0x0000000000000000      0x0000000000000000
0x55e9d0c5df30: 0x0000000000000000      0x0000000000000000
0x55e9d0c5df40: 0x0000000000000000      0x0000000000000000
0x55e9d0c5df50: 0x0000000000000000      0x0000000000000000
0x55e9d0c5df60: 0x0000000000000000      0x000055e9d0c60ab0
0x55e9d0c5df70: 0x0000000000000570      0x000055e9d0c61c00
0x55e9d0c5df80: 0x0000000000004000      0x0000000000000031
```

So comparing to the `key` struct, the we know the `shield_prekey_len` is 0x4000, so from that use intuition to fill in (from [sshkey.h](https://github.com/openssh/openssh-portable/blob/master/sshkey.h)):

```c
struct sshkey {
	//... (snipped)
	/* Private key shielding */
	u_char	*shielded_private;	// 0x000055e9d0c60ab0
	size_t	shielded_len;		// 0x0000000000000570
	u_char	*shield_prekey;		// 0x000055e9d0c61c00
	size_t	shield_prekey_len;	// 0x0000000000004000
};
```

Because one of SSH's security features is that the private key is never stored in plaintext, to avoid just this type of attack, where someone core dumps and gets the private key, we will need to recompile ssh-keygen and feed those shielded keys into it so we can get a nice private key we can use.
Lets dump the `shielded_private` and `shield_prekey`:

```
(gdb) dump binary memory shielded_private 0x000055e9d0c60ab0 0x000055e9d0c60ab0 + 0x570
(gdb) dump binary memory shield_prekey 0x000055e9d0c61c00 0x000055e9d0c61c00 + 0x4000
```

We're done with gdb for a bit. Now we need to generate the private key from here, so lets download and compile it the binary to do so:
```
$ wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.6p1.tar.gz
(snipped)

$ tar xvfz openssh-8.6p1.tar.gz && rm openssh-8.6p1.tar.gz && cd openssh-8.6p1
(snipped)

$ ./configure --with-audit=debug
(snipped)

$ make ssh-keygen
(snipped)
```

Now that we compiled the source, we can open `ssh-keygen` in gdb and call the needed functions (following this [amazing writeup](https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/) we can just use the same commands):

```
$ gdb -q ./ssh-keygen
(gdb) b main
(gdb) b sshkey_free
(gdb) r

(gdb) set $miak = (struct sshkey *)sshkey_new(0)
(gdb) set $shielded_private = (unsigned char *)malloc(1392)
(gdb) set $shield_prekey = (unsigned char *)malloc(16384)

(gdb) set $fd = fopen("../shielded_private", "r")
(gdb) call fread($shielded_private, 1, 1392, $fd)
(gdb) call fclose($fd)

(gdb) set $fd = fopen("../shield_prekey", "r")
(gdb) call fread($shield_prekey, 1, 16384, $fd)
(gdb) call fclose($fd)

(gdb) set $miak->shielded_private=$shielded_private
(gdb) set $miak->shield_prekey=$shield_prekey
(gdb) set $miak->shielded_len=1392
(gdb) set $miak->shield_prekey_len=16384

(gdb) call sshkey_unshield_private($miak)
(gdb) bt
(gdb) f 1
(gdb) x *kp
(gdb) call sshkey_save_private(*kp, "../../privatekey.pem", "", "0xfbad was here", 0, "\x00", 0)
(gdb) k
(gdb) q
```

Awesome we got the [private key](privatekey.pem)! Lets convert the key into an actual pem file so we can use it with openssl:

```
$ sudo ssh-keygen -p -f privatekey.pem -m pem
Key has comment '0xfbad was here'
Enter new passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved with the new passphrase.
```

And then decrypt the data:
```
$ openssl pkeyutl -decrypt -inkey privatekey.pem -in ./provided/data.enc -out data.txt
```

We got it, looking into the [data](data.txt) we can see the token of the cookie.

Submit:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTMzMzY3OTIsImV4cCI6MTY1NTkyODc5Miwic2VjIjoiWURHbDlPcjZDUDIyZGRBN2NROUFZMDE1UzNRbm5xbXMiLCJ1aWQiOjI4NTA0fQ.aqQHbAhbiF_1gH33DVlGY0eVQxwK4IbTuFAROxUMa8M
```

![Task Screenshot](https://i.imgur.com/IerdqDa.png)

> ```
> Great job!
> ```

<!-- TL;DR -->
## Technical TL;DR
Because we know the source of the ssh-agent, we can reverse our way up to find the shielded private and prekey. Then we can use the openssh source to locally build a copy of ssh-keygen and regenerate the private key using the shielded private and prekey. From there simply decrypt the data using openssh after making the key useable.

<div align="center">

[return to top](#top)

</div>
