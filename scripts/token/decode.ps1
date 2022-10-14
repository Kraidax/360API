$response = Invoke-RestMethod 'http://localhost:8008/decode/eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjQyIiwiZXhwIjoxNjQ4MDA2MTg3fQ.S2gRBbeCzS_3RBLJi-x3VykdIAyxBJ1dcJvO1YSlRXQ'


$people = $response

Write-Output $people