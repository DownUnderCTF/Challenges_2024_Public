import { Response } from "express";
import { encode } from "html-entities";

const BROWSER_REDIRECT = `<html>
    <body>
        <script>
            window.location = "{REDIRECT}";
        </script>
    </body>
</html>`;

const sendError = (res: Response, status: number, message: string) => {
    res.status(status).send({status: "error", data: {error: message}});
}

const sendResponse = (res: Response, data: object) => {
    res.status(200).send({status: "success", data: data});
}

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

export { sendError, sendResponse, sendBrowserRedirectResponse }