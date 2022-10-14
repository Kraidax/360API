$response = Invoke-RestMethod 'http://localhost:8008/elvcls/1'


$people = $response

Write-Output $people