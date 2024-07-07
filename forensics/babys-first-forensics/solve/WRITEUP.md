Pix's Writeup
============

Open the pcap up in your favourite pcap viewing program:
- `Wireshark`
- `TShark`
- `hexyl`
- `xxd`

Whatever you like to peek the bytes and things contained within.

This pcap is very straightforward and a whole lot of noise between two ip's.

We want to find out what tool has been used to generate all this traffic - Given looks like 
something of a brute force attempt to see files behind the scene you might be tempted 
to lead with something like `dirbuster` or `gobuster`.

However if you were to look at the User Agent contained within any of the request packets
you'll see the following:

```
|00282570│ 00 00 01 01 08 0a 01 a2 ┊ 6d dd 00 1c ba 79 47 45 │⋄⋄•••_•×┊m×⋄•×yGE│
│00282580│ 54 20 2f 63 67 69 2d 62 ┊ 69 6e 2f 74 65 73 74 2d │T /cgi-b┊in/test-│
│00282590│ 63 67 69 3f 2f 2a 20 48 ┊ 54 54 50 2f 31 2e 31 0d │cgi?/* H┊TTP/1.1_│
│002825a0│ 0a 43 6f 6e 6e 65 63 74 ┊ 69 6f 6e 3a 20 4b 65 65 │_Connect┊ion: Kee│
│002825b0│ 70 2d 41 6c 69 76 65 0d ┊ 0a 55 73 65 72 2d 41 67 │p-Alive_┊_User-Ag│
│002825c0│ 65 6e 74 3a 20 4d 6f 7a ┊ 69 6c 6c 61 2f 35 2e 30 │ent: Moz┊illa/5.0│
│002825d0│ 30 20 28 4e 69 6b 74 6f ┊ 2f 32 2e 31 2e 36 29 20 │0 (Nikto┊/2.1.6) │
│002825e0│ 28 45 76 61 73 69 6f 6e ┊ 73 3a 4e 6f 6e 65 29 20 │(Evasion┊s:None) │
│002825f0│ 28 54 65 73 74 3a 30 30 ┊ 31 30 32 32 29 0d 0a 48 │(Test:00┊1022)__H│
│00282600│ 6f 73 74 3a 20 31 37 32 ┊ 2e 31 36 2e 31 37 2e 31 │ost: 172┊.16.17.1
```

Or in plain text:
```
GET /cgi-bin/test-cgi?/*HTTP/1.1__Connection: 
Keep-Alive__User-Agent: Mozilla/5.0 0 (Nikto/2.1.6) (Evasions:None) 
(Test:001022)__Host: 172.16.17.1
```

Which should give away that the tool in use is in fact, nikto!
