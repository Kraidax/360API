$params = @{
	# "id_groupe" = "1"
	"id_eleve" = "11"
	"id_groupe" = "2";

}

$reponse = Invoke-WebRequest -Uri http://localhost:8008/neweleve_groupe -Method POST -Body ($params|ConvertTo-Json) -ContentType "application/json"


$people = $response

Write-Output $people