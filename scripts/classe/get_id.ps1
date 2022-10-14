$response = Invoke-RestMethod 'http://localhost:8008/getclasse/1'


$people = $response

Write-Output $people