$params = @{
	"id_projet" = "1"
	"id_elvnoteur" = "1"
	"id_elvnote" = "2"
	"note" = "17,5";

}

$reponse = Invoke-WebRequest -Uri http://localhost:8008/newnote -Method POST -Body ($params|ConvertTo-Json) -ContentType "application/json"


$people = $response

Write-Output $people