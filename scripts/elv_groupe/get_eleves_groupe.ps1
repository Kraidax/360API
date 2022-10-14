$response = Invoke-RestMethod 'http://localhost:8008/get_elv_by_grp/1'


$people = $response

Write-Output $people