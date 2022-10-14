$response = Invoke-RestMethod 'http://localhost:8008/getgroupes'


$people = $response

Write-Output $people