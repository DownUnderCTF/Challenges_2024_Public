Pix's Writeup
============

I can't believe they would lock up Kookaburras x( 

Maybe they were sick of being laughed at...

Lets connect to the server...
```
 ____  __.             __          ___.                               
|    |/ _|____   ____ |  | _______ \_ |__  __ _____________________   
|      < /  _ \ /  _ \|  |/ /\__  \ | __ \|  |  \_  __ \_  __ \__  \  
|    |  (  <_> |  <_> )    <  / __ \| \_\ \  |  /|  | \/|  | \// __ \_
|____|__ \____/ \____/|__|_ \(____  /___  /____/ |__|   |__|  (____  /
        \/                 \/     \/    \/                         \/ 
  ___ ___        .__       .___.__                                    
 /   |   \  ____ |  |    __| _/|__| ____    ____                      
/    ~    \/  _ \|  |   / __ | |  |/    \  / ___\                     
\    Y    (  <_> )  |__/ /_/ | |  |   |  \/ /_/  >                    
 \___|_  / \____/|____/\____ | |__|___|  /\___  /                     
       \/                   \/         \//_____/                      
_________        .__  .__                                             
\_   ___ \  ____ |  | |  |   ______                                   
/    \  \/_/ __ \|  | |  |  /  ___/                                   
\     \___\  ___/|  |_|  |__\___ \                                    
 \______  /\___  >____/____/____  >                                   
        \/     \/               \/                                    
```

Interesting, holding cells and they want a password, lets be smarter hackers and not just brute 
force the connection.

If we pop this `server` binary in something like `cutter` or Binary Ninja, we can go a 
peeking for anything interesting!

Running through a list of quick interesting keywords like "connect", "password", "username" 
"authentication", "auth" etc. We will get a hit for a few of them given its an SSH server.

However if we look inside the `RunSSH` function, and then further narrow down into the 
`WithPasswordAuth` we see that there is a check against the value:
`ManIReallyHateThoseDamnKookaburras!`
And given we've seen mention of this inside: `WithPasswordAuthentication` we could reasonably 
come to the conclusion this might be a potential password!

Which if we are enterprising souls, we extract and try as the potential password when connecting 
to the ssh server. Most Excellent, we're in.

( Another way to find this value is to take search for the word 'kookaburra' which you 
could extrapolate from the banner greeting you 'Kookaburras Holding Cells'. )
```
Welcome, pix!
This is the Kookaburra holding cells.
    Contained: 11912 Kookaburras
    -> No valid command
```

Cool.. but.. thats not a flag?!

Lets go back to the binary:

Given that this is a Go Binary, we know that they put user defined functions at the bottom of the 
disassembly ( unless there is some funky things going on ). So we know that there are only 
realistically 3-4 functions that are worth looking at. This narrows our search space pretty quickly.

Lets think about the messages we've been given so far. Kookaburra holding cells, 11912 birds and 
no valid command. <- Lets look at this, maybe there is a command field somewhere in here.

Looking into the breakdown inside `cutter` we can see there is a sess variable that is used by 
`charmbracelet/ssh` and it has a `Command()` value associated with it ( a []string ).

We can also see further along the disassembly that there is a path that leads to a string 
being printed that says "Welcome Warden" which we didn't get! So that must be what we need to 
have a 'valid command'. It also retrieves something from the env named `WARDEN`.

So lets connect the dots between the two, what is the condition to trigger us reaching the welcome 
message
```c
 if (((*piVar10 == 0x68546b636f6c6e55) &&
      (iVar4 = 0x6c654365, *(int32_t *)(piVar10 + 1) == 0x6c654365)) &&
      (*(int16_t *)((int64_t)piVar10 + 0xc) == 0x736c)) {
```

Looking at the if surrounding the above condition, if we take the hex here and piece it back together
we'll get the string: `"slleCehTkcolnU"` or reversed: `"UnlockTheCells"`

Now we just need to figure out how to send a command..
Thankfully, Linux man pages are well documented so we can go peek: [SSH](https://linux.die.net/man/1/ssh)

Which tells us that we can just do: `ssh <addr> "command"`

Running ssh against the server once more with "UnlockTheCells" as our command gets us the flag:

`DUCTF{L00K_WhO53_L4uGh1nG-N0w-H4HaH4Hah4hA}`

You freed the Kookaburras! <3 


