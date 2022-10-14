$response = Invoke-RestMethod 'http://localhost:8008/getnote/1'


$people = $response

Write-Output $people