$params = @{
	# "id" = "2"
	"nom" = "projet b";
	"id_classe" = "1"
}

$reponse=Invoke-WebRequest -Uri http://localhost:8008/newprojet -Method POST -Body ($params|ConvertTo-Json) -ContentType "application/json"


$people = $response

Write-Output $people