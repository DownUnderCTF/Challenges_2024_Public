import { Request, Response, NextFunction } from "express";
import { sendError } from "../utils/response";

const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    if (req.session.user !== process.env.ADMIN_USER) {
        sendError(res, 403, "nope")
        return 
    }
    next();
}

export default authMiddleware;