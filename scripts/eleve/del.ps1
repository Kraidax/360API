$response = Invoke-RestMethod -Uri 'http://localhost:8008/deleleve/3' -Method DELETE


$people = $response

Write-Output $people