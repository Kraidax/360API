use crate::models::{Eleve,NewEleve};
use crate::schema::eleves::dsl::*;
use crate::models::{Classe,NewClasse};
use crate::schema::classes::dsl::*;
use crate::models::{Projet,NewProjet};
use crate::schema::projets::dsl::*;
use crate::models::{Groupe,NewGroupe};
use crate::schema::groupes::dsl::*;
use crate::models::{Note,NewNote};
use crate::schema::notes::dsl::*;
use crate::models::{ElevesGroupe,NewElevesGroupe};
use crate::schema::eleves_groupe::dsl::*;
use crate::Pool;
use crate::diesel::QueryDsl;
use crate::diesel::RunQueryDsl;
use crate::diesel::ExpressionMethods;
use actix_web::{web, Error, HttpResponse};
use diesel::dsl::{delete, insert_into, update};
use serde::{Deserialize, Serialize};
use std::vec::Vec;
use chrono::prelude::*;
use lettre::Message;
use rusoto_ses::{RawMessage, SendRawEmailRequest, Ses, SesClient};
use std::env;
use rusoto_credential::{EnvironmentProvider, ProvideAwsCredentials};
use tokio::runtime::Runtime;
use jsonwebtoken::{encode, Algorithm, Header, EncodingKey,decode, DecodingKey, Validation};
use std::pin::Pin;
use regex::Regex;
use validator::Validate;
use lazy_static::lazy_static;


lazy_static! {
        static ref REGEX_MAIL: Regex = Regex::new(r"^[a-z0-9\-](\.?[a-z0-9\-]){3,50}@isen.yncrea\.fr$").unwrap();
    }
lazy_static! {
        static ref REGEX_NOM: Regex = Regex::new(r"^[A-Z]?[a-z0-9\- 'éèàùçêâûîôïöäëü]{1,50}$").unwrap();
    }
lazy_static! {
        static ref REGEX_ID: Regex = Regex::new(r"^[1-9][0-9]{0,5}$").unwrap();
    }
lazy_static! {
        static ref REGEX_NOTE: Regex = Regex::new(r"^[0-9]{1,2}|([0-9]{1,2})(,5)|20$").unwrap();
    }
lazy_static! {
        static ref REGEX_COMMENTAIRE: Regex = Regex::new(r"^[A-Za-z0-9\- 'éèàùçêâûîôïöäëü.?!;./,()]{1,500}$").unwrap();
    }


//////////////////////////////////////////////////// Rôle //////////////////////////////////////////

fn verif_role(      // Vérifie les token et renvoie le rôle de l'utilisateur
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

////////////////////////////////////////////// Token ///////////////////////////////////////////////

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    id: String,
    role: String,
    exp: usize,
}

fn read_token(      // Renvoie l'ID contenu dans le token
    token: web::Path<String>,
) -> i32 {

    let token_data = decode::<Claims>(&token, &DecodingKey::from_secret("U34$UrSB".as_ref()), &Validation::new(Algorithm::HS256)).unwrap();

    let id_str = token_data.claims.id;
    let id = id_str.parse::<i32>().unwrap();
    return id
}


///////////////////////////////////////////// Elève ////////////////////////////////////////////////


#[derive(Serialize, Deserialize, Validate)]
pub struct InputEleve {
    #[validate(
    regex(
    path = "REGEX_NOM",
    message = "Le nom doit contenir entre 2 et 50 caracteres"
    )
    )]
    pub nom: String,
    #[validate(
    regex(
    path = "REGEX_NOM",
    message = "Le prenom doit contenir entre 2 et 50 caracteres"
    )
    )]
    pub prenom: String,
    #[validate(
    regex(
    path = "REGEX_MAIL",
    message = "L'adresse mail doit être une adresse isen.yncrea"
    )
    )]
    pub mail: String,
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id doit etre un entier > 0"
    )
    )]
    pub id_classe: String,
}



pub async fn get_eleve(     // Récupère un élève selon son ID
    db: web::Data<Pool>,
    eleve_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let role = verif_role(req);
    if  role != "prof" && (role != "eleve") {
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = eleves
        .find(eleve_id.into_inner())
        .get_result::<Eleve>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_eleve| HttpResponse::Ok().json(other_eleve))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}



pub async fn get_eleves(        // Récupère tous les élèves
    db: web::Data<Pool>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = eleves.load::<Eleve>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_eleve| HttpResponse::Ok().json(other_eleve))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}



pub async fn create_eleve(       // Ajoute un élève
    db: web::Data<Pool>,
    input_eleve: web::Json<InputEleve>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {

    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let is_valid = input_eleve.validate();
    match is_valid {
        Ok(_) => (),
        Err(err) => return Ok(HttpResponse::BadRequest().json(err)),

    };
    let new_eleve = NewEleve {
        nom: &input_eleve.nom,
        prenom: &input_eleve.prenom,
        mail: &input_eleve.mail,
        id_classe: &input_eleve.id_classe,
    };
    let inserted_count = insert_into(eleves)
        .values(&new_eleve)
        .execute(&db.get().unwrap());

    Ok(web::block(move || inserted_count)
        .await
        .map(|other_eleve| HttpResponse::Created().json(other_eleve))
        .map_err(|_| HttpResponse::InternalServerError())?)
}



pub async fn delete_eleve(      // Supprime un élève
    db: web::Data<Pool>,
    eleve_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let count = delete(eleves.find(eleve_id.as_ref())).execute(&db.get().unwrap());

    Ok(
        web::block(move || count)
            .await
            .map(|other_eleve| HttpResponse::Ok().json(other_eleve))
            .map_err(|_| HttpResponse::InternalServerError())?,
    )
}



///////////////////////////////////////////// Table classes ////////////////////////////////////////


#[derive(Serialize, Deserialize, Validate)]
pub struct InputClasse {
    #[validate(
    regex(
    path = "REGEX_NOM",
    message = "Le nom doit contenir entre 2 et 50 caracteres"
    )
    )]
    pub nom: String,
}


pub async fn get_classe(        // Récupère une classe selon son ID
    db: web::Data<Pool>,
    classe_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = classes
        .find(classe_id.into_inner())
        .get_result::<Classe>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_classe| HttpResponse::Ok().json(other_classe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}

pub async fn get_classes(       // Récupère toutes les classes
    db: web::Data<Pool>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = classes.load::<Classe>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_classe| HttpResponse::Ok().json(other_classe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn create_classe(     // Ajoute une classe
    db: web::Data<Pool>,
    input_classe: web::Json<InputClasse>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let is_valid = input_classe.validate();
    match is_valid {
        Ok(_) => (),
        Err(err) => return Ok(HttpResponse::BadRequest().json(err)),

    };
    let new_classe = NewClasse {
        nom: &input_classe.nom,
    };
    let inserted_count = insert_into(classes)
        .values(&new_classe)
        .execute(&db.get().unwrap());

    Ok(web::block(move || inserted_count)
        .await
        .map(|other_classe| HttpResponse::Created().json(other_classe))
        .map_err(|_| HttpResponse::InternalServerError())?)
}



pub async fn delete_classe(     // Supprime une classe selon son ID
    db: web::Data<Pool>,
    classe_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let count = delete(classes.find(classe_id.as_ref())).execute(&db.get().unwrap());

    Ok(
        web::block(move || count)
            .await
            .map(|other_classe| HttpResponse::Ok().json(other_classe))
            .map_err(|_| HttpResponse::InternalServerError())?,
    )
}



//////////////////////////////////////// Table projets /////////////////////////////////////////////


#[derive(Serialize, Deserialize, Validate)]    pub struct InputProjet {

    #[validate(
    regex(
    path = "REGEX_NOM",
    message = "Le nom doit contenir entre 2 et 50 caracteres"
    )
    )]
    pub nom: String,

    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id' doit être un entier > 0"
    )
    )]
    pub id_classe: String,
}


pub async fn get_projet(        // Récupère un projet selon son ID
    db: web::Data<Pool>,
    projet_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = projets
        .find(projet_id.into_inner())
        .get_result::<Projet>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_projet| HttpResponse::Ok().json(other_projet))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}

pub async fn get_projets(       // Récupère tous les projets
    db: web::Data<Pool>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = projets.load::<Projet>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_projet| HttpResponse::Ok().json(other_projet))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn create_projet(     // Ajoute un projet
    db: web::Data<Pool>,
    input_projet: web::Json<InputProjet>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let is_valid = input_projet.validate();
    match is_valid {
        Ok(_) => (),
        Err(err) => return Ok(HttpResponse::BadRequest().json(err)),

    };
    let new_projet = NewProjet {
        nom: &input_projet.nom,
        id_classe: &input_projet.id_classe,
    };
    let inserted_count = insert_into(projets)
        .values(&new_projet)
        .execute(&db.get().unwrap());

    Ok(web::block(move || inserted_count)
        .await
        .map(|other_projet| HttpResponse::Created().json(other_projet))
        .map_err(|_| HttpResponse::InternalServerError())?)
}



pub async fn delete_projet(     // Supprime un projet selon son ID
    db: web::Data<Pool>,
    projet_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let count = delete(projets.find(projet_id.as_ref())).execute(&db.get().unwrap());

    Ok(
        web::block(move || count)
            .await
            .map(|other_projet| HttpResponse::Ok().json(other_projet))
            .map_err(|_| HttpResponse::InternalServerError())?,
    )
}


///////////////////////////////////////////// Table groupes ////////////////////////////////////////


#[derive(Serialize, Deserialize, Validate)]
pub struct InputGroupe {
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id doit etre un entier > 0"
    )
    )]
    pub id_projet: String,
    #[validate(
    regex(
    path = "REGEX_NOM",
    message = "Le nom doit contenir entre 2 et 50 caracteres"
    )
    )]
    pub nom: String,
}


pub async fn get_groupe(        // Récupère un groupe selon son ID
    db: web::Data<Pool>,
    groupe_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = groupes
        .find(groupe_id.into_inner())
        .get_result::<Groupe>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_groupe| HttpResponse::Ok().json(other_groupe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}

pub async fn get_groupes(       // Récupère tous les groupes
    db: web::Data<Pool>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = groupes.load::<Groupe>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_groupe| HttpResponse::Ok().json(other_groupe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn create_groupe(     // Ajoute un groupe
    db: web::Data<Pool>,
    input_groupe: web::Json<InputGroupe>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let is_valid = input_groupe.validate();
    match is_valid {
        Ok(_) => (),
        Err(err) => return Ok(HttpResponse::BadRequest().json(err)),

    };
    let new_groupe = NewGroupe {
        id_projet: &input_groupe.id_projet,
        nom: &input_groupe.nom,
    };
    let inserted_count = insert_into(groupes)
        .values(&new_groupe)
        .execute(&db.get().unwrap());

    Ok(web::block(move || inserted_count)
        .await
        .map(|other_groupe| HttpResponse::Created().json(other_groupe))
        .map_err(|_| HttpResponse::InternalServerError())?)
}



pub async fn delete_groupe(     // Supprime un groupe
    db: web::Data<Pool>,
    groupe_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let count = delete(groupes.find(groupe_id.as_ref())).execute(&db.get().unwrap());

    Ok(
        web::block(move || count)
            .await
            .map(|other_groupe| HttpResponse::Ok().json(other_groupe))
            .map_err(|_| HttpResponse::InternalServerError())?,
    )
}


pub async fn get_groupes_by_projet(     // Récupère tous les groupes associés à un projet donné
    db: web::Data<Pool>,
    value: web::Path<String>,
    req: actix_web::HttpRequest,
) ->  Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let items = groupes
        .filter(crate::schema::groupes::dsl::id_projet.eq(&value.to_string()))
        .load::<Groupe>(&db.get().unwrap());


    Ok(
        web::block(move || items)
            .await
            .map(|other_eleve| HttpResponse::Ok().json(other_eleve))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,)

}


////////////////////////////////////////////// Table notes /////////////////////////////////////////


#[derive(Serialize, Deserialize, Validate)]
pub struct InputNote {
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id doit etre un entier > 0"
    )
    )]
    pub id_groupe: String,
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id doit etre un entier > 0"
    )
    )]
    pub id_elvnoteur: String,
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id doit etre un entier > 0"
    )
    )]
    pub id_elvnote: String,
    #[validate(
    regex(
    path = "REGEX_NOTE",
    message = "La note doit etre comprise entre 0 et 20"
    )
    )]
    pub note: String,
    #[validate(
    regex(
    path = "REGEX_COMMENTAIRE",
    message = "Commentaire invalide"
    )
    )]
    pub commentaire: String,
}


pub async fn get_note(      // Récupère une note selon son ID
    db: web::Data<Pool>,
    note_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = notes
        .find(note_id.into_inner())
        .get_result::<Note>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_note| HttpResponse::Ok().json(other_note))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}

pub async fn get_notes(     // Récupère toutes les notes
    db: web::Data<Pool>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = notes.load::<Note>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_note| HttpResponse::Ok().json(other_note))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn create_note(       // Ajoute une note
    db: web::Data<Pool>,
    input_note: web::Json<InputNote>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {

    let token_opt = req
        .headers()
        .get("token");
    if token_opt.is_none(){
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let is_valid = input_note.validate();
    match is_valid {
        Ok(_) => (),
        Err(err) => return Ok(HttpResponse::BadRequest().json(err)),

    };

    let token: &str = token_opt
        .unwrap()
        .to_str()
        .unwrap();


    let token_data = decode::<Claims>(&token, &DecodingKey::from_secret("U34$UrSB".as_ref()), &Validation::new(Algorithm::HS256)).unwrap();
    let id_elvgrp = token_data.claims.id;
    if verif_role(req) != "eleve"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let id_elvgrp_note = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&id_elvgrp.parse::<i32>().unwrap()))
        .select(crate::schema::eleves_groupe::dsl::id_eleve)
        .get_result::<String>(&db.get().unwrap());

    let id_elvgrp_note = match id_elvgrp_note {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };

    if id_elvgrp_note != input_note.id_elvnoteur {
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let id = notes
        .filter(crate::schema::notes::dsl::id_elvnoteur.eq(&input_note.id_elvnoteur))
        .filter(crate::schema::notes::dsl::id_elvnote.eq(&input_note.id_elvnote))
        .filter(crate::schema::notes::dsl::id_groupe.eq(&input_note.id_groupe))
        .select(crate::schema::notes::dsl::id_note)
        .get_result::<i32>(&db.get().unwrap());

    let id = match id {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };

    let _updated_row = Pin::new(&mut update(notes
        .filter(crate::schema::notes::dsl::id_note.eq(&id)))
        .set((crate::schema::notes::dsl::note.eq(&input_note.note), crate::schema::notes::dsl::commentaire.eq(&input_note.commentaire), crate::schema::notes::dsl::fiche.eq("R"))))
        .execute(&db.get().unwrap());

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body("OK"))
}



pub async fn delete_note(       // Supprime une note
    db: web::Data<Pool>,
    note_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let count = delete(notes.find(note_id.as_ref())).execute(&db.get().unwrap());

    Ok(
        web::block(move || count)
            .await
            .map(|other_note| HttpResponse::Ok().json(other_note))
            .map_err(|_| HttpResponse::InternalServerError())?,
    )
}

fn calculate_moyenne(       //Calcule la moyenne d'un élève selon son id et son groupe
    db: &web::Data<Pool>,
    id_elv: String,
    id_grp: String,
) -> String {

    let list = notes
        .filter(crate::schema::notes::dsl::id_elvnote.eq(&id_elv))
        .filter(crate::schema::notes::dsl::id_groupe.eq(&id_grp))
        .filter(crate::schema::notes::dsl::fiche.eq("R"))
        .select(crate::schema::notes::dsl::note)
        .get_results::<String>(&db.get().unwrap());
    let mut somme:f64 = 0.0;
    let mut x=0;

    let list = match list {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };
    let mut nte_finale;
    let mut nte;
    for i in &list {
        let nte_str = i.to_string();
        if nte_str.contains(",") {
            nte_finale=nte_str.replace(",",".");
            nte = nte_finale.parse::<f64>().unwrap();
        }
        else {
            nte = nte_str.parse::<f64>().unwrap();
        }

        somme = somme + nte;
        x = x + 1;
    }
    let moy = somme as f64 / x as f64;

    let moy_str = moy.to_string();

    return moy_str
}

pub async fn get_moyenne(       // Récupère la moyenne d'un eleve_groupe
    db: web::Data<Pool>,
    id_elvgrp2: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let id_elvgrp = id_elvgrp2.clone();

    let id_inter = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&id_elvgrp))
        .select(crate::schema::eleves_groupe::dsl::id_eleve)
        .get_result::<String>(&db.get().unwrap());
    let id_inter = match id_inter {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };

    let id_inter2 = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&id_elvgrp))
        .select(crate::schema::eleves_groupe::dsl::id_groupe)
        .get_result::<String>(&db.get().unwrap());
    let id_inter2 = match id_inter2 {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };
    let id_grp = id_inter2.to_string();

    let id_elv = id_inter.to_string();

    let moy = calculate_moyenne(&db, id_elv, id_grp);

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body(moy))
}

pub async fn get_moyenne_groupe(        // Récupère la moyenne d'un groupe
    db: web::Data<Pool>,
    id_grp: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let list_elv = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_groupe.eq(&id_grp.to_string()))
        .select(crate::schema::eleves_groupe::dsl::id_eleve)
        .get_results::<String>(&db.get().unwrap());

    let list_elv = match list_elv {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };
    let mut moy_grp:f64 = 0.0;
    let mut nb_elv = 0;
    let mut elv;

    for j in &list_elv {
        elv = j.to_string();
        let moy_eleve = calculate_moyenne(&db,elv,id_grp.to_string());
        if moy_eleve.ne("NaN") {
            let moy_eleve_f = moy_eleve.parse::<f64>().unwrap();
            moy_grp = moy_grp + moy_eleve_f;
            nb_elv = nb_elv + 1;
        }
    }
    let moy_grp = moy_grp / nb_elv as f64;
    let moy_str = moy_grp.to_string();
    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body(moy_str))
}

//////////////////////////////////////// Table eleves_groupes //////////////////////////////////////


#[derive(Serialize, Deserialize, Validate)]
pub struct InputElevesGroupe {
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id doit etre un entier > 0"
    )
    )]
    pub id_eleve: String,
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "L'id doit etre un entier > 0"
    )
    )]
    pub id_groupe: String,
}


pub async fn get_eleves_groupe(     // Récupère un eleve_groupe selon son ID
    db: web::Data<Pool>,
    eleves_groupe_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let role = verif_role(req);
    if role != "prof" && role != "eleve"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = eleves_groupe
        .find(eleves_groupe_id.into_inner())
        .get_result::<ElevesGroupe>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_eleves_groupe| HttpResponse::Ok().json(other_eleves_groupe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}

pub async fn get_eleves_groupes(    // Récupère tous les eleve_groupe
    db: web::Data<Pool>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let result = eleves_groupe.load::<ElevesGroupe>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_eleves_groupe| HttpResponse::Ok().json(other_eleves_groupe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn create_eleves_groupe(      // Ajoute un eleve_groupe
    db: web::Data<Pool>,
    input_eleves_groupe: web::Json<InputElevesGroupe>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let is_valid = input_eleves_groupe.validate();
    match is_valid {
        Ok(_) => (),
        Err(err) => return Ok(HttpResponse::BadRequest().json(err)),

    };
    let new_eleves_groupe = NewElevesGroupe {
        id_eleve: &input_eleves_groupe.id_eleve,
        id_groupe: &input_eleves_groupe.id_groupe,
    };
    let inserted_count = insert_into(eleves_groupe)
        .values(&new_eleves_groupe)
        .execute(&db.get().unwrap());

    Ok(web::block(move || inserted_count)
        .await
        .map(|other_eleves_groupe| HttpResponse::Created().json(other_eleves_groupe))
        .map_err(|_| HttpResponse::InternalServerError())?)
}



pub async fn delete_eleves_groupe(      // Supprime un eleve_groupe
    db: web::Data<Pool>,
    eleves_groupe_id: web::Path<i32>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let count = delete(eleves_groupe.find(eleves_groupe_id.as_ref())).execute(&db.get().unwrap());

    Ok(
        web::block(move || count)
            .await
            .map(|other_eleves_groupe| HttpResponse::Ok().json(other_eleves_groupe))
            .map_err(|_| HttpResponse::InternalServerError())?,
    )
}


pub async fn get_id_noteur(     // Récupère l'id de l'élève dont le token a été passé dans l'URL
    db: web::Data<Pool>,
    token: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "eleve"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let value = read_token(token);
    let result = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&value))
        .select(crate::schema::eleves_groupe::dsl::id_eleve)
        .get_result::<String>(&db.get().unwrap());

    Ok(
        web::block(move || result)
            .await
            .map(|other_eleves_groupe| HttpResponse::Ok().json(other_eleves_groupe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn get_groupe_by_token(       // Récupère le groupe pour lequel la fiche 360 doit être remplie
    db: web::Data<Pool>,
    token: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "eleve"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let value : i32 = read_token(token);

    let id_inter = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&value))
        .select(crate::schema::eleves_groupe::dsl::id_groupe)
        .get_result::<String>(&db.get().unwrap());

    let id_inter = match id_inter {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };

    let id_str = id_inter.to_string();
    let id = id_str.parse::<i32>().unwrap();

    let result = groupes
        .filter(crate::schema::groupes::dsl::id_groupe.eq(&id))
        .load::<Groupe>(&db.get().unwrap());
		
    Ok(
        web::block(move || result)
            .await
            .map(|other_eleves_groupe| HttpResponse::Ok().json(other_eleves_groupe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn get_projet_by_token(       //Récupère le projet pour lequel la fiche 360 doit être remplie
    db: web::Data<Pool>,
    token: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "eleve"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let value : i32 = read_token(token);
    let id_inter = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&value))
        .select(crate::schema::eleves_groupe::dsl::id_groupe)
        .get_result::<String>(&db.get().unwrap());

    let id_inter = match id_inter {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };

    let id_str = id_inter.to_string();
    let id = id_str.parse::<i32>().unwrap();

    let projet = groupes
        .select(crate::schema::groupes::dsl::id_projet)
        .filter(crate::schema::groupes::dsl::id_groupe.eq(&id))
        .get_result::<String>(&db.get().unwrap());
		
	let projet = match projet {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };

	let projet_int = projet.parse::<i32>().unwrap();

	let result = projets
		.filter(crate::schema::projets::dsl::id_projet.eq(&projet_int))
		.get_result::<Projet>(&db.get().unwrap());
		
    Ok(
        web::block(move || result)
            .await
            .map(|other_eleves_groupe| HttpResponse::Ok().json(other_eleves_groupe))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,
    )
}


pub async fn get_eleves_by_groupe(      // Récupère les élèves appartenant au même groupe que l'eleve_groupe dont le token a été passé dans l'URL
    db: web::Data<Pool>,
    token: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "eleve"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let value : i32 = read_token(token);
    let id_inter = eleves_groupe
        .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&value))
        .select(crate::schema::eleves_groupe::dsl::id_groupe)
        .get_result::<String>(&db.get().unwrap());

    let id_inter = match id_inter {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };

    let id = id_inter.to_string();

    let list_id = eleves_groupe
        .select(crate::schema::eleves_groupe::dsl::id_eleve)
        .filter(crate::schema::eleves_groupe::dsl::id_groupe.eq(&id))
        .load::<String>(&db.get().unwrap());

    let list_id = match list_id {
        Ok(valeur) => valeur,
        Err(error) => panic!("Error: {:?}", error),
    };
    let mut result:Vec<Eleve> = Vec::new();
    for id_str in list_id {
        let id_int = id_str.parse::<i32>().unwrap();
        let value = eleves
            .filter(crate::schema::eleves::dsl::id_eleve.eq(&id_int))
            .get_result::<Eleve>(&db.get().unwrap());
        let value = match value {
            Ok(valeur) => valeur,
            Err(error) => panic!("Error: {:?}", error),
        };
        result.push(value);
    }

	let json = serde_json::to_string(&result)?;
	Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(json))
}

pub async fn get_eleves_by_classe(      // Récupère tous les élèves appartenant à une classe
    db: web::Data<Pool>,
    value: web::Path<String>,
    req: actix_web::HttpRequest,
) ->  Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }
    let items = eleves
        .filter(crate::schema::eleves::dsl::id_classe.eq(&value.to_string()))
        .load::<Eleve>(&db.get().unwrap());


    Ok(
        web::block(move || items)
            .await
            .map(|other_eleve| HttpResponse::Ok().json(other_eleve))
            .map_err(|_| HttpResponse::NotFound().json("not found"))?,)

}






//////////////////////////////////////////////// MAIL //////////////////////////////////////////////

#[derive(Serialize, Deserialize, Validate)]
pub struct InputMail {
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "Valeur invalide"
    )
    )]
    pub total: String,
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "Valeur invalide"
    )
    )]
    pub count: String,
    #[validate(
    regex(
    path = "REGEX_ID",
    message = "Valeur invalide"
    )
    )]
    pub eleve_id: String,
}


pub async fn send_mail(     // Envoie un mail à un élève_groupe
    db: web::Data<Pool>,
    infos: web::Json<InputMail>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let count = &infos.count;
    let total = &infos.total;
    let eleve_id = &infos.eleve_id;

     match env::var("PRIO") {
         Ok(val) => env::set_var("PRIO", val),
         Err(_e) => env::set_var("PRIO", "1"),}

     while env::var("PRIO").unwrap().ne(count) {
     }

    let rt = Runtime::new().unwrap();


        let expiration = Utc::now().checked_add_signed(chrono::Duration::days(60)).expect("valid timestamp").timestamp();

        let my_claims = Claims {
            id: eleve_id.to_owned(),
            role: "eleve".to_string(),
            exp: expiration as usize,
        };
        let mut header = Header::default();
        header.alg = Algorithm::HS256;
        let token = encode(&header, &my_claims, &EncodingKey::from_secret("U34$UrSB".as_ref())).unwrap();

        let token_data = decode::<Claims>(&token, &DecodingKey::from_secret("U34$UrSB".as_ref()), &Validation::new(Algorithm::HS256)).unwrap();



        let id_str = token_data.claims.id;
        let value = id_str.parse::<i32>().unwrap();

        let id_grp = eleves_groupe
            .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&value))
            .select(crate::schema::eleves_groupe::dsl::id_groupe)
            .get_result::<String>(&db.get().unwrap());

        let id_grp = match id_grp {
            Ok(valeur) => valeur,
            Err(error) => panic!("Error: {:?}", error),
        };

        let liste_a_noter = eleves_groupe
            .filter(crate::schema::eleves_groupe::dsl::id_groupe.eq(&id_grp))
            .select(crate::schema::eleves_groupe::dsl::id_eleve)
            .get_results::<String>(&db.get().unwrap());

        let liste_a_noter = match liste_a_noter {
            Ok(valeur) => valeur,
            Err(error) => panic!("Error: {:?}", error),
        };

        let id_unique_str = eleves_groupe
            .filter(crate::schema::eleves_groupe::dsl::id_eg.eq(&value))
            .select(crate::schema::eleves_groupe::dsl::id_eleve)
            .get_result::<String>(&db.get().unwrap());

        let id_unique_str = match id_unique_str {
            Ok(valeur) => valeur,
            Err(error) => panic!("Error: {:?}", error),
        };

        let id_unique = id_unique_str.parse::<i32>().unwrap();


        for i in &liste_a_noter{

            let new_note = NewNote {
                id_groupe: &id_grp,
                id_elvnoteur: &id_unique_str,
                id_elvnote: i,
                note: "0",
                commentaire: "NULL",
                fiche: "E",
            };
            let _inserted_count = insert_into(notes)
                .values(&new_note)
                .execute(&db.get().unwrap());
        }

    rt.block_on(async {
        env::set_var("AWS_ACCESS_KEY_ID", "AKIA3ARADIHD6CPPG4AS");
        env::set_var("AWS_SECRET_ACCESS_KEY", "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");

        let creds = EnvironmentProvider::with_prefix("AWS").credentials().await.unwrap();

        assert_eq!(creds.aws_access_key_id(), "AKIA3ARADIHD6CPPG4AS");
        assert_eq!(creds.aws_secret_access_key(), "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");
        assert!(creds.expires_at().is_none());

        let ses_client = SesClient::new(rusoto_core::Region::EuWest3);

        let from = "<noreply.notation360@gmail.com>";

        let items = eleves
            .filter(crate::schema::eleves::dsl::id_eleve.eq(&id_unique))
            .select(crate::schema::eleves::dsl::mail)
            .get_result::<String>(&db.get().unwrap());

        let items = match items {
            Ok(valeur) => valeur,
            Err(error) => panic!("Error: {:?}", error),
        };

        let to = items.to_string();

        let subject;
        match env::var("SUJET_MAIL") {
            Ok(val) => subject = val,
            Err(_e) => subject = "Demande de notation 360".to_string(),}

        let body;
        match env::var("BODY_MAIL") {
            Ok(val) => body = val,
            Err(_e) => body = "Veuillez noter le projet à l'adresse suivante : ".to_string(),}

        let url = "localhost:4201/token/".to_owned() + &token.to_string();
        let body_complet = body.to_owned() + " " + &url;


        send_email_ses(&ses_client, from, &to, &subject, body_complet).await;

        if env::var("PRIO").unwrap().eq(total) {
            env::set_var("PRIO", "1")
        }
        else {
            env::set_var("PRIO", (env::var("PRIO").unwrap().parse::<i32>().unwrap() + 1).to_string());
        }
    });

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body("OK"))

}

async fn send_email_ses(        // Envoi de mail
    ses_client: &SesClient,
    from: &str,
    to: &str,
    subject: &str,
    body: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .body(body.to_string())?;

    let raw_email = email.formatted();

    let ses_request = SendRawEmailRequest {
        raw_message: RawMessage {
            data: base64::encode(raw_email).into(),
        },
        ..Default::default()
    };


    ses_client.send_raw_email(ses_request).await?;


    Ok(())
}


#[derive(Serialize, Deserialize, Validate)]
pub struct InputText {
    #[validate(
    regex(
    path = "REGEX_COMMENTAIRE",
    message = "Texte invalide"
    )
    )]
    pub text: String,
}


pub async fn modif_sujet(       // Modifie l'objet du mail envoyé aux élèves
    modif: web::Json<InputText>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    env::set_var("SUJET_MAIL", modif.text.to_string());

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body("OK"))
}



pub async fn modif_body(        // Modifie le corps du mail à envoyer aux élèves
    modif: web::Json<InputText>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    env::set_var("BODY_MAIL", modif.text.to_string());

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body("OK"))
}

pub async fn print_sujet(       // Récupère le corps du mail à envoyer aux élèves
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let sujet;
    match env::var("SUJET_MAIL") {
        Ok(val) => sujet = val,
        Err(_e) => sujet = "Définissez le sujet du mail.".to_string(),
    }

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body(sujet))
}

pub async fn print_body(        // Récupère le corps du mail à envoyer aux élèves
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    let body;
    match env::var("BODY_MAIL") {
        Ok(val) => body = val,
        Err(_e) => body = "Définissez le corps du mail.".to_string(),
    }

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body(body))
}

pub async fn rappel_mail(       // Envoie un mail aux élèves d'un groupe qui n'ont pas rempli leur fiche 360
    db: web::Data<Pool>,
    id_grp: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    if verif_role(req) != "prof"{
        return Ok(actix_web::HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Permission denied"));
    }

    match env::var("MAIL") {
        Ok(val) => env::set_var("MAIL", val),
        Err(_e) => env::set_var("MAIL", "0"),}

    while env::var("MAIL").unwrap() == "1"  {
    }

    env::set_var("MAIL", "1");

    let rt = Runtime::new().unwrap();

    rt.block_on(async {

        env::set_var("AWS_ACCESS_KEY_ID", "AKIA3ARADIHD6CPPG4AS");
        env::set_var("AWS_SECRET_ACCESS_KEY", "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");

        let creds = EnvironmentProvider::with_prefix("AWS").credentials().await.unwrap();

        assert_eq!(creds.aws_access_key_id(), "AKIA3ARADIHD6CPPG4AS");
        assert_eq!(creds.aws_secret_access_key(), "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");
        assert!(creds.expires_at().is_none());

        let ses_client = SesClient::new(rusoto_core::Region::EuWest3);

        let from = "<noreply.notation360@gmail.com>";


        let subject = "Rappel notation 360";

        let body = "Vous n'avez pas rempli votre fiche de notation 360.";


        let list_id = notes
            .filter(crate::schema::notes::dsl::id_groupe.eq(&id_grp.to_string()))
            .filter(crate::schema::notes::dsl::fiche.eq("E"))
            .select(crate::schema::notes::dsl::id_elvnoteur)
            .get_results::<String>(&db.get().unwrap());

        let list_id = match list_id {
            Ok(valeur) => valeur,
            Err(error) => panic!("Error: {:?}", error),
        };


        let mut list_id_unique: Vec<String> = Vec::new();

        for i in 0..list_id.len() {
            let id = &list_id[i];
            let mut x = 1;
            let mut y = 0;
            while (i+x)<list_id.len() {
                if list_id[i + x].eq(id) {
                    y = y + 1;
                }
                x = x + 1
            }
            if y == 0 {
                list_id_unique.push(id.to_string())
            }
        }


        let mut list_mail: Vec<String> = Vec::new();

        for id_elv in list_id_unique {
            let id_elv_int = id_elv.parse::<i32>().unwrap();
            let value = eleves
                .filter(crate::schema::eleves::dsl::id_eleve.eq(&id_elv_int))
                .select(crate::schema::eleves::dsl::mail)
                .get_result::<String>(&db.get().unwrap());

            let value = match value {
                Ok(valeur) => valeur,
                Err(error) => panic!("Error: {:?}", error),
            };

            list_mail.push(value);

        }


        for mail_elv in list_mail {
            let to = mail_elv.to_string();
            send_email_ses(&ses_client, from, &to, &subject.to_string(), body.to_string()).await;
        }

        env::set_var("MAIL", "0");

    });

    Ok(actix_web::HttpResponse::Ok()
        .content_type("text/plain")
        .body("OK"))
}
