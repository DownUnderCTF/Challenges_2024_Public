#[macro_use] extern crate rocket;

mod guards;
mod responders;

use rocket::fs::NamedFile;
use rocket::serde::{ json::Json, Deserialize, Serialize};
use rocket::response::Redirect;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::fs;
use rand::{distributions::Alphanumeric, Rng};

use guards::auth::{ JWT, create_jwt };
use responders::error::{ ErrorResponse, ErrorJson };

// Serve static files from the /static folder
#[get("/<file..>")]
async fn files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}

#[get("/")]
fn index() -> Redirect {
    let redirect = Redirect::to(uri!("/index.html"));
    redirect
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token: String
}

#[post("/login", format = "application/json", data = "<login_request>")]
fn login(login_request: Json<LoginRequest>) -> Result<Json<LoginResponse>, ErrorResponse> {
    /* TODO: Remove hardcoded user */
    if login_request.username == "jooospeh" && login_request.password == "n3v3r-g0nna-g1v3-th3-b1rds-up" {
        match create_jwt(0) {
            Ok(token) => Ok(Json(LoginResponse { token: token.to_string() })),
            Err(_) => Err(ErrorResponse::InternalServerError(Json(ErrorJson{error: "Internal Server Error".to_string()})))
        }
    } else {
        Err(ErrorResponse::Unauthorized(Json(ErrorJson{error: "Incorrect Username or Password".to_string()})))
    }
}

#[derive(Serialize)]
pub struct FlagResponse {
    flag: String
}

#[get("/flag")]
fn flag(jwt: Result<JWT, ErrorResponse>) -> Result<Json<FlagResponse>, ErrorResponse> {
    let jwt = jwt?;
    if jwt.claims.subject_id == 1 {
        let flag = fs::read_to_string("flag.txt")
            .expect("Unable to read flag.txt in the same directory.");

        Ok(Json(FlagResponse{flag: flag}))
    } else {
        Err(ErrorResponse::WrappedUnauthorized(Json(ErrorJson{error: format!("Subject {} does not have permissions to view this flag.", jwt.claims.subject_id)})))
    }
}

#[derive(Serialize)]
pub struct EnvResponse {
    message: String,
    filename: String
}
#[post("/env", data = "<input>")]
fn post_env(input: &[u8]) -> Result<Json<EnvResponse>, ErrorResponse> {
    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    match fs::File::create(format!("loot/{}", s)) {
        Ok(mut file) => {
            file.write_all("This file intentionally left blank.".as_bytes()).unwrap();
            Ok(Json(EnvResponse{ message: "Uploaded succeeded".to_string(), filename: s }))
        }
        Err(e) => Err(ErrorResponse::InternalServerError(Json(ErrorJson{error: format!("Internal Server Error: {e:?}").to_string()})))
    }
    
}

#[get("/env")]
fn get_env_all() -> Result<Json<Vec<String>>, ErrorResponse> {
    let paths = fs::read_dir("loot/").unwrap().map(|x| x.unwrap().path().file_name().unwrap().to_os_string().into_string().unwrap()).collect();
    Ok(Json(paths))
}

#[get("/env/<id>")]
async fn get_env_spesific(id: String) -> Option<NamedFile> {
    NamedFile::open(Path::new("loot/").join(id)).await.ok()
}

#[launch]
fn rocket() -> _ {
    rocket::build()
    .mount("/api", routes![login, flag, post_env, get_env_all, get_env_spesific])
    .mount("/", routes![index, files])
}
