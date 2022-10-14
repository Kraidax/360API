$response = Invoke-RestMethod -Uri 'http://localhost:8008/delnote/1' -Method DELETE


$people = $response

Write-Output $people