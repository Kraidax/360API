$response = Invoke-RestMethod 'http://localhost:8008/geteleve_groupe/1'


$people = $response

Write-Output $people