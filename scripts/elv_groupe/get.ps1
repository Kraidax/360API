$response = Invoke-RestMethod 'http://localhost:8008/geteleves_groupes'


$people = $response

Write-Output $people