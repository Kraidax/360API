extern crate bcrypt;
extern crate jsonwebtoken as jwt;

use super::models::{NewUser};
use super::schema::users::dsl::*;
use super::Pool;
use crate::diesel::QueryDsl;
use crate::diesel::RunQueryDsl;
use crate::diesel::ExpressionMethods;
use actix_web::{web, Error, HttpResponse};
use diesel::dsl::{insert_into};
use serde::{Deserialize, Serialize};
use bcrypt::{ hash, verify};
use chrono::prelude::*;
use jsonwebtoken::{encode, Algorithm, Header, EncodingKey,decode, DecodingKey, Validation};
use actix_web::cookie::Cookie;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
	id: String,
	role: String,
	exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputSignUp {
    pub username: String,
    pub pswd: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputSignIn {
    pub username: String,
    pub pswd: String,
}

fn verif_role(		// Vérifie les token et renvoie le rôle de l'utilisateur
	req: actix_web::HttpRequest,
) -> String {
	let role;
	let role_cookie;
	let token_opt = req
		.headers()
		.get("token");
	if token_opt.is_none() {
		role = "erreur".to_string();
	} else {
		let token: &str = token_opt
			.unwrap()
			.to_str()
			.unwrap();
		let token_data = decode::<Claims>(&token, &DecodingKey::from_secret("U34$UrSB".as_ref()), &Validation::new(Algorithm::HS256)).unwrap();
		let role_str = token_data.claims.role;
		role = role_str.parse::<String>().unwrap();
	}
	if role == "prof" {
		let token_opt_cookie = req
			.headers()
			.get("cookie");

		if token_opt_cookie.is_none() {
			role_cookie = "erreur".to_string();
		} else {
			let token_cookie = token_opt_cookie
				.unwrap()
				.to_str()
				.unwrap()
				.replace("token=", "");

			let token_data_cookie = decode::<Claims>(&token_cookie, &DecodingKey::from_secret("2XY00hT$".as_ref()), &Validation::new(Algorithm::HS256)).unwrap();
			let role_str_cookie = token_data_cookie.claims.role;
			role_cookie = role_str_cookie.parse::<String>().unwrap();
		}
		return if role == role_cookie {
			role
		} else {
			"erreur".to_string()
		}
	}
	else if role == "eleve" {
		return role
	}
	else {
		return "erreur".to_string()
	}
}

pub async fn create_user(		// Crée un compte
    db: web::Data<Pool>,
    input: web::Json<InputSignUp>,
	req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {

	let role = verif_role(req);
	if  role != "prof" && (role != "eleve") {
		return Ok(actix_web::HttpResponse::Unauthorized()
			.content_type("text/plain")
			.body("Permission denied"));
	}
	
	let hash_pswd = hash(&input.pswd, 10).expect("Mot de passe hashé");

	let new_user = NewUser {
		username: &input.username,
		hash: &hash_pswd,
	};	

    let inserted_count = insert_into(users)
        .values(&new_user)
        .execute(&db.get().unwrap());

    Ok(web::block(move || inserted_count)
        .await
        .map(|other_user| HttpResponse::Created().json(other_user))
        .map_err(|_| HttpResponse::InternalServerError())?)
}


pub async fn sign_in(		 // Vérifie que les identifiants de connexion sont valides, renvoie un token et en met un en cookie si c'est le cas
    db: web::Data<Pool>,
    input: web::Json<InputSignUp>,
) -> Result<HttpResponse, Error> {

	let hash_pswd = users
		.select(crate::schema::users::dsl::hash)
		.filter(username.eq(&input.username))
		.get_result::<String>(&db.get().unwrap()).expect("hash du mot de passe");
		
	if verify(&input.pswd, &hash_pswd).expect("hashs vérifiés") == true {
		
		let expiration = Utc::now().checked_add_signed(chrono::Duration::hours(1)).expect("valid timestamp").timestamp();

		let my_claims = Claims {
			id: "0".to_string(),
			role: "prof".to_string(),
			exp: expiration as usize,
		};
		let mut header = Header::default();
		header.alg = Algorithm::HS256;
		let token = encode(&header, &my_claims, &EncodingKey::from_secret("U34$UrSB".as_ref())).unwrap();
		let token_cookie = encode(&header, &my_claims, &EncodingKey::from_secret("2XY00hT$".as_ref())).unwrap();

		let auth_cookie = Cookie::build("token", token_cookie)
			.domain("localhost")
			.path("/")
			//.secure(true)
			//.http_only(true)
			.finish();

		Ok(actix_web::HttpResponse::Ok()
			.content_type("text/plain")
			.cookie(auth_cookie)
			.body(token))
	}
	
	else{
		Ok(actix_web::HttpResponse::NotFound()
			.content_type("text/plain")
			.body("User not found"))
	}
}