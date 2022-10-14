$response = Invoke-RestMethod -Uri 'http://localhost:8008/delclasse/1' -Method DELETE


$people = $response

Write-Output $people