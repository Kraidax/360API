$response = Invoke-RestMethod 'http://localhost:8008/get_grp_by_prjt/4'


$people = $response

Write-Output $people