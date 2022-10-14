table! {
    classes (id_classe) {
        id_classe -> Integer,
        nom -> Text,
    }
}

table! {
    eleves (id_eleve) {
        id_eleve -> Integer,
        nom -> Text,
        prenom -> Text,
        mail -> Text,
        id_classe -> Text,
    }
}

table! {
    eleves_groupe (id_eg) {
        id_eg -> Integer,
        id_eleve -> Text,
        id_groupe -> Text,
    }
}

table! {
    groupes (id_groupe) {
        id_groupe -> Integer,
        id_projet -> Text,
        nom -> Text,
    }
}

table! {
    notes (id_note) {
        id_note -> Integer,
        id_groupe -> Text,
        id_elvnoteur -> Text,
        id_elvnote -> Text,
        note -> Text,
        commentaire -> Text,
        fiche -> Text,
    }
}

table! {
    projets (id_projet) {
        id_projet -> Integer,
        nom -> Text,
        id_classe -> Text,
    }
}

table! {
    users (id_user) {
        id_user -> Integer,
        username -> Text,
        hash -> Text,
    }
}

allow_tables_to_appear_in_same_query!(
    classes,
    eleves,
    eleves_groupe,
    groupes,
    notes,
    projets,
    users,
);
