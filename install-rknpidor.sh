$t = (Get-Clipboard -Raw) -replace "`r`n","`n"
$b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t))
gh api -X PUT repos/SkiTreIne/rknpidor/contents/install-rknpidor.sh -f message=init -f content=$b