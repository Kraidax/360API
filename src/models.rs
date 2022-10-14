use crate::schema::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct Eleve {
    pub id_eleve: i32,
    pub nom: String,
    pub prenom: String,
    pub mail: String,
    pub id_classe: String,
}

#[derive(Insertable, Debug)]
#[table_name = "eleves"]
pub struct NewEleve<'a> {
    pub nom: &'a str,
    pub prenom: &'a str,
    pub mail: &'a str,
    pub id_classe: &'a str,
}

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct Projet {
    pub id_projet: i32,
    pub nom: String,
	pub id_classe: String,
}

#[derive(Insertable, Debug)]
#[table_name = "projets"]
pub struct NewProjet<'a> {
    pub nom: &'a str,
    pub id_classe: &'a str,
}

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct Groupe {
    pub id_groupe: i32,
	pub id_projet: String,
	pub nom: String,
}

#[derive(Insertable, Debug)]
#[table_name = "groupes"]
pub struct NewGroupe<'a> {
	pub id_projet: &'a str,
    pub nom: &'a str,
}


#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct Note {
    pub id_note: i32,
	pub id_groupe: String,
	pub id_elvnoteur: String,
	pub id_elvnote: String,
	pub note: String,
	pub commentaire: String,
    pub fiche: String,
}

#[derive(Insertable, Debug)]
#[table_name = "notes"]
pub struct NewNote<'a> {
    pub id_groupe: &'a str,
	pub id_elvnoteur: &'a str,
	pub id_elvnote: &'a str,
	pub note: &'a str,
	pub commentaire: &'a str,
    pub fiche: &'a str,
}

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct Classe {
    pub id_classe: i32,
	pub nom: String,

}

#[derive(Insertable, Debug)]
#[table_name = "classes"]
pub struct NewClasse<'a> {
    pub nom: &'a str,
}

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct ElevesGroupe {
    pub id_eg: i32,
	pub id_eleve: String,
	pub id_groupe: String,
}

#[derive(Insertable, Debug)]
#[table_name = "eleves_groupe"]
pub struct NewElevesGroupe<'a> {
    pub id_eleve: &'a str,
	pub id_groupe: &'a str,
}

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct User {
    pub id_user: i32,
	pub username: String,
    pub hash: String,
}

#[derive(Insertable, Debug)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub hash: &'a String,
}