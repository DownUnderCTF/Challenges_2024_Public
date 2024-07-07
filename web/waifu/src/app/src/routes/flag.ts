import { Request, Response, Router } from "express";
import authMiddleware from "../middleware/auth";
import { sendResponse } from "../utils/response";

const router = Router();
router.use(authMiddleware);

router.get("/", (req: Request, res: Response) => {
    res.sendFile("flag.html", { root: "html" });
})

router.get('/get', (req: Request, res: Response) => {
    sendResponse(res, { message: process.env.FLAG })
})

export default router