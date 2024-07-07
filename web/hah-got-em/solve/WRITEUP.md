hah got em
============

Goal for the challenge is to read `/etc/flag.txt` from the instance.

The challenge just pulls [`gotenberg` version 8.0.3](https://github.com/gotenberg/gotenberg/releases/tag/v8.0.3) and copies the flag in.

```Dockerfile
FROM gotenberg/gotenberg:8.0.3

COPY flag.txt /etc/flag.txt
```

Checking the version releases for `gotenberg`, there following version (8.1.0) was a security update, but there is no public PoC.

[Diffing v8.1.0 with v8.0.3 we can see that a new test case was added for file read](https://github.com/gotenberg/gotenberg/compare/v8.0.3...v8.1.0#diff-be84e06649ad8faf29f22ad46330a6e9b83dbaf2d6c35b2a3656313d26a79d35R67).

```html
<div class="page-break-after">
    <h2>/etc/passwd</h2>
    <iframe src="/etc/passwd"></iframe>

    <h2>\\localhost/etc/passwd</h2>
    <iframe src="\\localhost/etc/passwd"></iframe>
</div>
```

Alternatively, [this regex](https://github.com/gotenberg/gotenberg/compare/v8.0.3...v8.1.0#diff-76ed074a9305c04054cdebb9e9aad2d818052b07091de1f20cad0bbac34ffb52L48) was insecure and you could bypass using `/proc/self/root`.

[The `index.html` shows both solutions](./index.html) and [`solve.sh` executes a curl command](./solve.sh) to convert the HTML to PDF.