$params = @{
	# "id_groupe" = "1"
	"id_projet" = "4"
	"nom" = "chevaux de feu";

}

$reponse = Invoke-WebRequest -Uri http://localhost:8008/newgroupe -Method POST -Body ($params|ConvertTo-Json) -ContentType "application/json"


$people = $response

Write-Output $people