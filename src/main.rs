#[macro_use]
extern crate diesel;

use actix_web::{web, App, HttpServer};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

mod eleves;
mod schema;
mod models;
mod auth;


pub type Pool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

//use openssl::ssl::{SslFiletype, SslMethod, SslAcceptor};		// Decommenter pour le HTTPS

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
	dotenv::dotenv().ok();
	std::env::set_var("RUST_LOG", "actix_web=debug");
	let database_url = "db";

	//let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();		// Decommenter les 3 lignes pour le HTTPS
	//builder.set_private_key_file("./certif/key.pem", SslFiletype::PEM).unwrap();
	//builder.set_certificate_chain_file("./certif/cert.pem").unwrap();

	let manager = ConnectionManager::<SqliteConnection>::new(database_url);
	let db: Pool = r2d2::Pool::builder()
		.max_size(100)
		.build(manager)
		.expect("Failed to create pool.");

	HttpServer::new(move || {

		App::new()
			.data(db.clone())
			.route("/neweleve", web::put().to(eleves::create_eleve))
			.route("/geteleves", web::get().to(eleves::get_eleves))
			.route("/geteleve/{id}", web::get().to(eleves::get_eleve))
			.route("/deleleve/{id}", web::delete().to(eleves::delete_eleve))
			.route("/getid_noteur/{token}", web::get().to(eleves::get_id_noteur))
			.route("/get_elv_by_grp/{token}", web::get().to(eleves::get_eleves_by_groupe))
			.route("/elvcls/{id}", web::get().to(eleves::get_eleves_by_classe))

			.route("/newclasse", web::put().to(eleves::create_classe))
			.route("/getclasses", web::get().to(eleves::get_classes))
			.route("/getclasse/{id}", web::get().to(eleves::get_classe))
			.route("/delclasse/{id}", web::delete().to(eleves::delete_classe))

			.route("/newprojet", web::put().to(eleves::create_projet))
			.route("/getprojets", web::get().to(eleves::get_projets))
			.route("/getprojet/{id}", web::get().to(eleves::get_projet))
			.route("/delprojet/{id}", web::delete().to(eleves::delete_projet))
			.route("/get_projet_by_token/{token}", web::get().to(eleves::get_projet_by_token))

			.route("/newgroupe", web::put().to(eleves::create_groupe))
			.route("/getgroupes", web::get().to(eleves::get_groupes))
			.route("/getgroupe/{id}", web::get().to(eleves::get_groupe))
			.route("/delgroupe/{id}", web::delete().to(eleves::delete_groupe))
			.route("/get_grp_by_prjt/{id}", web::get().to(eleves::get_groupes_by_projet))
			.route("/get_groupe_by_token/{token}", web::get().to(eleves::get_groupe_by_token))

			.route("/neweleve_groupe", web::put().to(eleves::create_eleves_groupe))
			.route("/geteleves_groupes", web::get().to(eleves::get_eleves_groupes))
			.route("/geteleve_groupe/{id}", web::get().to(eleves::get_eleves_groupe))
			.route("/deleleve_groupe/{id}", web::delete().to(eleves::delete_eleves_groupe))

			.route("/modif_body", web::put().to(eleves::modif_body))
			.route("/modif_sujet", web::put().to(eleves::modif_sujet))
			.route("/print_body", web::get().to(eleves::print_body))
			.route("/print_sujet", web::get().to(eleves::print_sujet))
			.route("/mail", web::post().to(eleves::send_mail))
			.route("/rappel/{id}", web::get().to(eleves::rappel_mail))

			.route("/newnote", web::put().to(eleves::create_note))
			.route("/getnotes", web::get().to(eleves::get_notes))
			.route("/getnote/{id}", web::get().to(eleves::get_note))
			.route("/delnote/{id}", web::delete().to(eleves::delete_note))

			.route("/moyenne/{id}", web::get().to(eleves::get_moyenne))
			.route("/moyenne_grp/{id}", web::get().to(eleves::get_moyenne_groupe))

			.route("/signup", web::put().to(auth::create_user))
			.route("/signin", web::post().to(auth::sign_in))

	})
		//.bind_openssl("localhost:8008", builder)?		// Pour lancer en HTTPS, commenter ligne 89 et decommenter ligne 88
		.bind("localhost:8008")?		// Pour lancer en HTTP, commenter ligne 88 et decommenter ligne 89
		.run()
		.await
}




