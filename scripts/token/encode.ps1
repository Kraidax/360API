$response = Invoke-RestMethod 'http://localhost:8008/encode/1'


$people = $response

Write-Output $people