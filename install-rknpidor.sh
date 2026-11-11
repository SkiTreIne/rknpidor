$t = (Get-Clipboard -Raw) -replace "`r`n","`n"
$b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t))
$sha = gh api repos/SkiTreIne/rknpidor/contents/install-rknpidor.sh --jq .sha 2>$null
if ($sha) { gh api -X PUT repos/SkiTreIne/rknpidor/contents/install-rknpidor.sh -f message=menu -f content=$b -f sha=$sha } else { gh api -X PUT repos/SkiTreIne/rknpidor/contents/install-rknpidor.sh -f message=init -f content=$b }