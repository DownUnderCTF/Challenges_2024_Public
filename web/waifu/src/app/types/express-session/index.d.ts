declare namespace Express {
    interface CustomSessionFields {
        user: string
    }

    export interface Request {
        session: Session & Partial<SessionData> & CustomSessionFields
    }
}