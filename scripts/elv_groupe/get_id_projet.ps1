$response = Invoke-RestMethod 'http://localhost:8008/getid_projet/2'


$people = $response

Write-Output $people