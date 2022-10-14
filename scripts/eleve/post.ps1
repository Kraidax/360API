$params = @{
	# "id" = "2"
	"nom" = "Duclaux";
	"prenom" = "Victor";
	"mail" = "victor.duclaux@isen.yncrea.fr";
	"id_classe" = "1";
}

$reponse=Invoke-WebRequest -Uri http://localhost:8008/neweleve -Method POST -Body ($params|ConvertTo-Json) -ContentType "application/json"


Write-Output $response