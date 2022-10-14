$response = Invoke-RestMethod 'http://localhost:8008/geteleve/4'


$people = $response

Write-Output $people