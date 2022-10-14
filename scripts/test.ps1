$response = Invoke-RestMethod 'http://localhost:8008/test/2'


$people = $response

Write-Output $people