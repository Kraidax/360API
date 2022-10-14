$response = Invoke-RestMethod 'http://localhost:8008/getclasses'


$people = $response

Write-Output $people