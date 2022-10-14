$response = Invoke-RestMethod -Uri 'http://localhost:8008/deleleve_groupe/1' -Method DELETE


$people = $response

Write-Output $people