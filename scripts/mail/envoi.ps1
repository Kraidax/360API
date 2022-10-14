$response = Invoke-RestMethod 'http://localhost:8008/mail/1'


$people = $response

Write-Output $people