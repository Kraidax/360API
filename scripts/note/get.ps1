$response = Invoke-RestMethod 'http://localhost:8008/getnotes'


$people = $response

Write-Output $people