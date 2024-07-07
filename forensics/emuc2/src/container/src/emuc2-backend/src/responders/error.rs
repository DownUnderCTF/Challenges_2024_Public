use rocket::{response::Responder, serde::json::Json};
use serde::Serialize;

#[derive(Debug, Responder, Serialize)]
pub struct ErrorJson {
    pub error: String,
}

#[derive(Debug, Responder)]
pub enum ErrorResponse {
    #[response(status = 401, content_type = "json")]
    Unauthorized(Json<ErrorJson>),
    #[response(status = 200, content_type = "json")]
    WrappedUnauthorized(Json<ErrorJson>),
    #[response(status = 500, content_type = "json")]
    InternalServerError(Json<ErrorJson>),
}