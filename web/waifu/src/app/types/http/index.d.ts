declare module "http" {
    interface IncomingMessage {
        rawBody: string
    }
}