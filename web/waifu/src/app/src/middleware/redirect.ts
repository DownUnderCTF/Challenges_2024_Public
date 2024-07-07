import { Request, Response, NextFunction } from "express";
import { sendBrowserRedirectResponse } from "../utils/response";

const redirectIfAuthMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    if (req.session.loggedIn === true) {
        const redirectTo = req.query.redirectTo as string ?? "/flag/";
        sendBrowserRedirectResponse(res, redirectTo);
        return
    }
    next();
}

export default redirectIfAuthMiddleware