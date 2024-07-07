import { Request, Response, Router } from "express";
import waifuMiddleware from "../middleware/waifu";
import redirectIfAuthMiddleware from "../middleware/redirect";
import { sendError, sendBrowserRedirectResponse } from "../utils/response";
import { rateLimit } from "express-rate-limit";

const router = Router();
router.use(rateLimit({
    windowMs: 5 * 60 * 100,
    limit: 5,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    message: { status: "error", data: { error: "rate limit has been hit!" } }
}))

// THIS IS NOT PART OF THE CHALLENGE! ONLY FOR THE BOT
router.get("/bot/login", (req: Request, res: Response) => {
    const token = req.query.token ?? '';
    console.log("Bot login attempt")
    if (typeof token !== 'string') {
        sendError(res, 400, "Missing token");
        return
    }

    if (token === process.env.BOT_TOKEN) {
        console.log("Bot login successful")
        req.session.user = process.env.ADMIN_USER;
        req.session.loggedIn = true;
        sendBrowserRedirectResponse(res, "/flag/");
        return
    }
    sendError(res, 400, "Nope");
})

router.use(waifuMiddleware);
router.use(redirectIfAuthMiddleware)

router.get("/", (req: Request, res: Response) => {
    res.sendFile("login.html", { root: "html" });
})

router.post("/login", (req: Request, res: Response) => {
    const { username, password } = req.body;
    if (!username || !password) {
        sendError(res, 400, "Missing username or password");
        return
    }
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASSWORD) {
        req.session.user = username;
        req.session.loggedIn = true;
        sendBrowserRedirectResponse(res, "/flag/");
        return
    }
    sendError(res, 401, "Invalid username or password");
});

export default router;
