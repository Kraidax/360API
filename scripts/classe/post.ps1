$params = @{
	# "id" = "2"
	"nom" = "M1";
}

$reponse=Invoke-WebRequest -Uri http://localhost:8008/newclasse -Method POST -Body ($params|ConvertTo-Json) -ContentType "application/json"


$people = $response

Write-Output $people