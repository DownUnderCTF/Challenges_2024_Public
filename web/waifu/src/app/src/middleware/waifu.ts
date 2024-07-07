import { Request, Response, NextFunction } from "express";
import { analyseRequest } from "../utils/chatGPT";
import { getRawRequest } from "../utils/request";
import { sendError } from "../utils/response";

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

export default waifuMiddleware