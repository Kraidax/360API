$response = Invoke-RestMethod -Uri 'http://localhost:8008/delgroupe/3' -Method DELETE


$people = $response

Write-Output $people