$response = Invoke-RestMethod 'http://localhost:8008/geteleves'


$people = $response

Write-Output $people