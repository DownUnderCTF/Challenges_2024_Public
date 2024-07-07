import { Request } from "express";

const getRawRequest = (req: Request): string => {
    const reqLines: Array<string> = [];
    reqLines.push(`${req.method} ${req.url} HTTP/${req.httpVersion}`);
    for (const header in req.headers) {
        reqLines.push(`${header}: ${req.headers[header]}`);
    }
    reqLines.push('');
    if (req.rawBody) {
        reqLines.push(req.rawBody);
    }
    return reqLines.join("\r\n");
}

export {
    getRawRequest
}