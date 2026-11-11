$null = Read-Host "Скопируй скрипт из ответа с меню и нажми Enter"
$t = (Get-Clipboard -Raw) -replace "`r`n","`n"
if ($t -notmatch '^#!/usr/bin/env bash') { throw "в буфере не скрипт" }
$b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t))
$sha = gh api repos/SkiTreIne/rknpidor/contents/install-rknpidor.sh --jq .sha
gh api -X PUT repos/SkiTreIne/rknpidor/contents/install-rknpidor.sh -f message=menu -f content=$b -f sha=$sha