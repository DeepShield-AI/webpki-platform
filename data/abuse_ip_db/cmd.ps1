
$headers = @{
    "Key" = "d6db5c926563fb1ac0282ea34442bb1e787addac9f32a663477f6ce023e4e7bbbabcf89034507ce2"
    "Accept" = "application/json"
}

$params = @{
    "limit" = "500000"
    "ipVersion" = "4"
    "plaintext" = ""
}

Invoke-WebRequest -Uri "https://api.abuseipdb.com/api/v2/blacklist" -Method Get -Headers $headers -Body $params |
    Select-Object -ExpandProperty Content |
    Out-File -FilePath "blacklist_plain.txt" -Encoding UTF8
    