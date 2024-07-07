## How to build this challenge:

1. Build the challenge container:
```
$ cd container

$ docker build -t chal .
```

2. Run the challenge container
```
$ docker run -p 1337:1337 chal

$ cd ..
```

3. Generate the pcap (replace localhost:1337 with the appropriate url for the challenge container):
```
$ cd pcap

$ docker build -t pcapgen . && docker run -v ./../../publish/:/output/ --net=host pcapgen localhost:1337
```

4. ???

5. Start the challenge with `publish/challenge.pcap` :D