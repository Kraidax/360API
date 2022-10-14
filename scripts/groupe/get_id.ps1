$response = Invoke-RestMethod 'http://localhost:8008/getgroupe/4'


$people = $response

Write-Output $people