import * as express from "express";
import * as session from "express-session";
import { randomBytes } from "crypto";
import { IncomingMessage, ServerResponse } from "http";
import authRouter from "./routes/auth";
import flagRouter from "./routes/flag";
import { sendBrowserRedirectResponse } from "./utils/response";

const app: express.Express = express();
app.use(session({ secret: randomBytes(32).toString("hex") }));
app.use(
    express.urlencoded({
        limit: '5mb',
        verify: (req: IncomingMessage, res: ServerResponse<IncomingMessage>, buf: Buffer) => {
            req.rawBody = buf.toString();
        }
    })
);
app.use(express.static('public'))
app.use("/auth", authRouter);
app.use("/flag", flagRouter);
app.get("/", (req: express.Request, res: express.Response) => sendBrowserRedirectResponse(res, "/auth/"));
app.listen(3000, () => console.log("Server is running on port 3000"))