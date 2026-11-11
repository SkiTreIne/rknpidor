#!/usr/bin/env bash
# install-rknpidor.sh: обертка над dotX12/traffic-guard
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "нужен root"; exit 1; }

export DEBIAN_FRONTEND=noninteractive
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get update -qq
apt-get install -y -qq iptables ipset iptables-persistent rsyslog whois curl ca-certificates

# чистка предыдущей версии (ipset rknp)
if iptables -L RKNP -n >/dev/null 2>&1; then
  for p in INPUT DOCKER-USER; do
    while iptables -D $p -j RKNP 2>/dev/null; do :; done
  done
  iptables -F RKNP || true
  iptables -X RKNP || true
  ipset destroy rknp 2>/dev/null || true
  ipset destroy rknp-wl 2>/dev/null || true
  systemctl disable --now rknpidor.timer 2>/dev/null || true
  rm -f /etc/systemd/system/rknpidor.timer
fi

mkdir -p /etc/rknpidor

[ -f /etc/rknpidor/sources.conf ] || cat > /etc/rknpidor/sources.conf <<'EOF'
# по одной ссылке на строку
https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list
EOF
[ -f /etc/rknpidor/whitelist.txt ] || echo "# свои IP/CIDR, по одному на строку" > /etc/rknpidor/whitelist.txt
[ -f /etc/rknpidor/blacklist.txt ] || echo "# ручной бан, IP/CIDR по одному на строку" > /etc/rknpidor/blacklist.txt

# защита от самоблокировки: текущий SSH-клиент в whitelist
ssh_ip="${SSH_CLIENT:-}"; ssh_ip="${ssh_ip%% *}"
if [ -n "$ssh_ip" ]; then
  grep -qxF "$ssh_ip" /etc/rknpidor/whitelist.txt || echo "$ssh_ip" >> /etc/rknpidor/whitelist.txt
fi

curl -fsSL https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh | bash
command -v traffic-guard >/dev/null || { echo "traffic-guard не установился"; exit 1; }

cat > /usr/local/bin/rknpidor <<'EOF'
#!/usr/bin/env bash
CONF=/etc/rknpidor
CH=SCANNERS-BLOCK
V4=SCANNERS-BLOCK-V4
V6=SCANNERS-BLOCK-V6
CSV=/var/log/iptables-scanners-aggregate.csv
SELF_URL="https://raw.githubusercontent.com/SkiTreIne/rknpidor/main/install-rknpidor.sh"

[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"

fam()  { [[ $1 == *:* ]] && echo ip6tables || echo iptables; }
setof() { [[ $1 == *:* ]] && echo $V6 || echo $V4; }
need() { [ -n "${1:-}" ] || { echo "нужен IP/CIDR"; exit 1; }; }
pause() { read -rp "Enter..." _ || true; }
cnt()   { ipset list "$1" -t 2>/dev/null | awk '/Number of entries/{print $4; f=1} END{if(!f)print 0}'; }
drops() { "$1" -nvxL $CH 2>/dev/null | awk '$3=="DROP"{s+=$1} END{print s+0}'; }

stats() {
  subs=$(( $(cnt $V4) + $(cnt $V6) ))
  hits=$(( $(drops iptables) + $(drops ip6tables) ))
}

apply() {
  iptables -L $CH -n >/dev/null 2>&1 || { echo "цепочка $CH не найдена, выполни: rknpidor update"; return 1; }
  for p in INPUT DOCKER-USER; do
    iptables -L $p -n >/dev/null 2>&1 || continue
    iptables -C $p -j $CH 2>/dev/null || iptables -I $p 1 -j $CH
  done
  grep -vE '^\s*(#|$)' $CONF/whitelist.txt | while read -r ip; do
    f=$(fam "$ip")
    $f -C $CH -s "$ip" -j RETURN 2>/dev/null || $f -I $CH 1 -s "$ip" -j RETURN
  done
  grep -vE '^\s*(#|$)' $CONF/blacklist.txt | while read -r ip; do
    ipset add "$(setof "$ip")" "$ip" -exist
  done
}

update() {
  local args=() u
  while read -r u; do args+=(-u "$u"); done < <(grep -vE '^\s*(#|$)' $CONF/sources.conf)
  [ ${#args[@]} -gt 0 ] || { echo "sources.conf пуст"; return 1; }
  traffic-guard full "${args[@]}" --enable-logging && apply && { stats; echo "ok: подсетей $subs"; }
}

boot() {
  if ipset list $V4 >/dev/null 2>&1 && iptables -L $CH -n >/dev/null 2>&1; then apply; else update; fi
}

status() {
  stats
  echo "подсетей: $subs, пакетов отбито: $hits"
  iptables -nvL $CH 2>/dev/null | head -20 || echo "правила выключены"
}

top() {
  [ -s "$CSV" ] || { echo "CSV пока пуст, логи копятся несколько минут"; return; }
  grep -v '^IP_TYPE' "$CSV" | sort -t'|' -k5,5nr | head -"${1:-20}" | awk -F'|' '
    BEGIN{printf "%-3s %-39s %-10s %-22s %6s\n","T","IP","ASN","NET","HITS"}
    {printf "%-3s %-39s %-10s %-22s %6s\n",$1,$2,$3,substr($4,1,22),$5}'
}

ban() {
  grep -qxF "$1" $CONF/blacklist.txt || echo "$1" >> $CONF/blacklist.txt
  ipset add "$(setof "$1")" "$1" -exist && echo "ban $1"
}
unban() {
  grep -vxF "$1" $CONF/blacklist.txt > $CONF/blacklist.tmp; mv $CONF/blacklist.tmp $CONF/blacklist.txt
  ipset del "$(setof "$1")" "$1" 2>/dev/null; echo "unban $1"
}
allow() {
  grep -qxF "$1" $CONF/whitelist.txt || echo "$1" >> $CONF/whitelist.txt
  f=$(fam "$1")
  $f -C $CH -s "$1" -j RETURN 2>/dev/null || $f -I $CH 1 -s "$1" -j RETURN
  echo "allow $1"
}
unallow() {
  grep -vxF "$1" $CONF/whitelist.txt > $CONF/whitelist.tmp; mv $CONF/whitelist.tmp $CONF/whitelist.txt
  f=$(fam "$1"); while $f -D $CH -s "$1" -j RETURN 2>/dev/null; do :; done
  echo "unallow $1"
}
check() {
  grep -qxF "$1" $CONF/whitelist.txt && echo "в whitelist"
  ipset test "$(setof "$1")" "$1" 2>&1
}

uninstall() {
  while iptables -D DOCKER-USER -j $CH 2>/dev/null; do :; done
  traffic-guard uninstall --yes --remove-logs
  systemctl disable --now rknpidor.service rknpidor-update.timer 2>/dev/null
  rm -f /etc/systemd/system/rknpidor.service /etc/systemd/system/rknpidor-update.service /etc/systemd/system/rknpidor-update.timer
  systemctl daemon-reload
  rm -rf $CONF /usr/local/bin/traffic-guard /usr/local/bin/rknpidor
  echo "удалено"
}

ipmenu() {
  while true; do
    echo
    echo "  1. Ban     2. Unban     3. Allow (whitelist)"
    echo "  4. Unallow 5. Check     0. Назад"
    read -rp "Выбор: " a || exit 0
    [ "$a" = 0 ] && return
    read -rp "IP/CIDR: " ip || exit 0
    [ -n "$ip" ] || continue
    case $a in
      1) ban "$ip" ;;
      2) unban "$ip" ;;
      3) allow "$ip" ;;
      4) unallow "$ip" ;;
      5) check "$ip" ;;
    esac
  done
}

menu() {
  trap ':' INT
  while true; do
    clear
    stats
    printf '\n  \033[36mRKNPIDOR MANAGER\033[0m\n  ------------------------------\n'
    printf '  Подсетей:        \033[32m%s\033[0m\n  Пакетов отбито:  \033[31m%s\033[0m\n\n' "$subs" "$hits"
    echo "  1. Топ атак (CSV)"
    echo "  2. Логи IPv4 (Live)"
    echo "  3. Логи IPv6 (Live)"
    echo "  4. Управление IP (Ban/Unban/Allow)"
    echo "  5. Обновить списки (Update)"
    echo "  6. Переустановить (Reinstall)"
    echo "  7. Удалить (Uninstall)"
    echo "  0. Выход"
    echo
    read -rp "Ваш выбор: " c || exit 0
    case $c in
      1) top 20; pause ;;
      2) tail -n 30 -f /var/log/iptables-scanners-ipv4.log ;;
      3) tail -n 30 -f /var/log/iptables-scanners-ipv6.log ;;
      4) ipmenu ;;
      5) update; pause ;;
      6) curl -fsSL "$SELF_URL" | bash; pause ;;
      7) read -rp "Удалить? [y/N]: " y || exit 0
         [ "$y" = y ] && { uninstall; exit 0; } ;;
      0) exit 0 ;;
    esac
  done
}

case "${1:-menu}" in
  menu)    menu ;;
  status)  status ;;
  update)  update ;;
  apply)   apply && echo ok ;;
  boot)    boot ;;
  top)     top "${2:-20}" ;;
  ban)     need "${2:-}"; ban "$2" ;;
  unban)   need "${2:-}"; unban "$2" ;;
  allow)   need "${2:-}"; allow "$2" ;;
  unallow) need "${2:-}"; unallow "$2" ;;
  check)   need "${2:-}"; check "$2" ;;
  uninstall) uninstall ;;
  *) echo "rknpidor [menu|status|update|apply|top [N]|ban IP|unban IP|allow IP|unallow IP|check IP|uninstall]" ;;
esac
EOF
chmod +x /usr/local/bin/rknpidor

cat > /etc/systemd/system/rknpidor.service <<'EOF'
[Unit]
Description=rknpidor apply rules at boot
After=network-online.target netfilter-persistent.service docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/rknpidor boot

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/rknpidor-update.service <<'EOF'
[Unit]
Description=rknpidor list update

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rknpidor update
EOF

cat > /etc/systemd/system/rknpidor-update.timer <<'EOF'
[Unit]
Description=rknpidor daily update

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
/usr/local/bin/rknpidor update
systemctl enable rknpidor.service rknpidor-update.timer
systemctl start rknpidor-update.timer
echo "готово: rknpidor"