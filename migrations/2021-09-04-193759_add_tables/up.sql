CREATE TABLE "eleves_groupe" (
	"id_eg" integer not null primary key autoincrement,
	"id_eleve" varchar not null,
	"id_groupe" varchar not null
);


CREATE TABLE "classes" (
	"id_classe" integer not null primary key autoincrement,
	"nom" varchar not null
);


CREATE TABLE "notes" (
	"id_note" integer not null primary key autoincrement,
	"id_projet" varchar not null,
	"id_elvnoteur" varchar not null,
	"id_elvnote" varchar not null,
	"note" varchar not null
);

CREATE TABLE "eleves" (
	"id_eleve" integer not null primary key autoincrement,
	"nom" varchar not null,
	"prenom" varchar not null,
	"mail" varchar not null,
	"id_classe" varchar not null
);


CREATE TABLE "projets" (
	"id_projet" integer not null primary key autoincrement,
	"nom" varchar not null ,
	"id_classe" varchar not null
);


CREATE TABLE "groupes" (
	"id_groupe" integer not null primary key autoincrement,
	"id_projet" varchar not null,
	"nom" varchar not null
);
