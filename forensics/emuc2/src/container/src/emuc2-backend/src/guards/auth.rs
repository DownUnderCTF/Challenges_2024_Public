use crate::responders::error::{ ErrorResponse, ErrorJson };

use jsonwebtoken::{ encode, decode, EncodingKey, DecodingKey, Algorithm, errors::ErrorKind, errors::Error, Header, Validation };
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::request::{self, Outcome, Request, FromRequest};
use rocket::http::Status;
use std::fs;

use chrono::Utc;

pub fn create_jwt(id: i32) -> Result<String, Error> {
    let secret = fs::read_to_string("secret.txt")
            .expect("Unable to read secret.txt in the same directory.");

    let expiration = Utc::now().checked_add_signed(chrono::Duration::seconds(60)).expect("Invalid timestamp").timestamp();
    
    let claims = Claims {
        subject_id: id,
        exp: expiration as usize
    }; 

    let header = Header::new(Algorithm::HS512);

    encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

pub fn decode_jwt(token: String) -> Result<Claims, ErrorKind> {
    let secret = fs::read_to_string("secret.txt")
            .expect("Unable to read secret.txt in the same directory.");

    let token = token.trim_start_matches("Bearer").trim();

    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS512),
     ) {
        Ok(token) => Ok(token.claims),
        Err(err) => Err(err.kind().to_owned())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub subject_id: i32,
    exp: usize
}

#[derive(Debug)]
pub struct JWT {
    pub claims: Claims
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for JWT {
    type Error = ErrorResponse;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        fn is_valid(key: &str) -> Result<Claims, ErrorKind> {
            decode_jwt(String::from(key))
        }

        match req.headers().get_one("authorization") {
            None => {
                Outcome::Error((Status::Unauthorized, ErrorResponse::Unauthorized(Json(ErrorJson{error: "Error validating JWT token - No token provided".to_string()}))))
            }
            Some(key) => match is_valid(key) {
                Ok(claims) => Outcome::Success(JWT {claims}),
                Err(err) => match &err {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        Outcome::Error((Status::Unauthorized, ErrorResponse::Unauthorized(Json(ErrorJson{error: "Error validating JWT token - Expired Token".to_string()}))))
                    },
                    jsonwebtoken::errors::ErrorKind::InvalidToken => {
                        Outcome::Error((Status::Unauthorized, ErrorResponse::Unauthorized(Json(ErrorJson{error: "Error validating JWT token - Invalid Token".to_string()}))))
                    },
                    _ => {
                        Outcome::Error((Status::Unauthorized, ErrorResponse::Unauthorized(Json(ErrorJson{error: format!("Error validating JWT token - {:?}", err)}))))
                    }
                }
            },
        }
    }
}