$response = Invoke-RestMethod 'http://localhost:8008/getprojet/4'


$people = $response

Write-Output $people