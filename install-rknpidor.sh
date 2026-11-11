#!/usr/bin/env bash
# install-rknpidor.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "нужен root"; exit 1; }

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ipset iptables curl ca-certificates

mkdir -p /etc/rknpidor /var/lib/rknpidor

[ -f /etc/rknpidor/sources.conf ] || cat > /etc/rknpidor/sources.conf <<'EOF'
# по одной ссылке на строку, плоские списки IPv4/CIDR
https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list
EOF

[ -f /etc/rknpidor/whitelist.txt ] || echo "# свои IP/CIDR, по одному на строку" > /etc/rknpidor/whitelist.txt
[ -f /etc/rknpidor/blacklist.txt ] || echo "# ручной бан, по одному IP/CIDR на строку" > /etc/rknpidor/blacklist.txt
if [ -n "${SSH_CLIENT:-}" ]; then
  ip="${SSH_CLIENT%% *}"
  grep -qxF "$ip" /etc/rknpidor/whitelist.txt || echo "$ip" >> /etc/rknpidor/whitelist.txt
fi

cat > /usr/local/bin/rknpidor <<'EOF'
#!/usr/bin/env bash
CONF=/etc/rknpidor
DATA=/var/lib/rknpidor
SET=rknp
WL=rknp-wl
CH=RKNP
SELF_URL="https://raw.githubusercontent.com/SkiTreIne/rknpidor/main/install-rknpidor.sh"

[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"

fetch() {
  local tmp; tmp=$(mktemp)
  grep -vE '^\s*(#|$)' $CONF/sources.conf | while read -r u; do
    curl -fsSL --max-time 60 "$u" >> "$tmp" || echo "fail: $u" >&2
  done
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$tmp" | sort -u > $DATA/list.new
  rm -f "$tmp"
  if [ "$(wc -l < $DATA/list.new)" -lt 10 ]; then
    echo "список пуст или сломан, оставляю старый" >&2
    rm -f $DATA/list.new
    return 1
  fi
  mv $DATA/list.new $DATA/list.txt
}

load() {
  ipset create $SET hash:net family inet maxelem 1000000 -exist
  ipset create $WL hash:net family inet -exist
  ipset create ${SET}-new hash:net family inet maxelem 1000000 -exist
  ipset flush ${SET}-new
  sed "s/^/add ${SET}-new /" $DATA/list.txt | ipset restore -exist
  grep -vE '^\s*(#|$)' $CONF/blacklist.txt | sed "s/^/add ${SET}-new /" | ipset restore -exist
  ipset swap $SET ${SET}-new
  ipset destroy ${SET}-new
  ipset flush $WL
  grep -vE '^\s*(#|$)' $CONF/whitelist.txt | while read -r ip; do ipset add $WL "$ip" -exist; done
}

rules() {
  iptables -N $CH 2>/dev/null || true
  iptables -F $CH
  iptables -A $CH -m set --match-set $WL src -j RETURN
  iptables -A $CH -m set --match-set $SET src -m limit --limit 5/min -j LOG --log-prefix "RKNP: "
  iptables -A $CH -m set --match-set $SET src -j DROP
  for p in INPUT DOCKER-USER; do
    iptables -L $p -n >/dev/null 2>&1 || continue
    iptables -C $p -j $CH 2>/dev/null || iptables -I $p 1 -j $CH
  done
}

unrules() {
  for p in INPUT DOCKER-USER; do
    while iptables -D $p -j $CH 2>/dev/null; do :; done
  done
  iptables -F $CH 2>/dev/null
  iptables -X $CH 2>/dev/null
}

top() {
  echo "ip,hits"
  journalctl -k --no-pager | grep 'RKNP:' | grep -o 'SRC=[0-9.]*' | cut -d= -f2 \
    | sort | uniq -c | sort -rn | head -${1:-20} | awk '{print $2","$1}'
}

pause() { read -rp "Enter..." _ || exit 0; }

ipmenu() {
  while true; do
    echo
    echo "  1. Ban      2. Unban      3. Allow (whitelist)"
    echo "  4. Unallow  5. Check      0. Назад"
    read -rp "Выбор: " a || exit 0
    [ "$a" = 0 ] && return
    read -rp "IP/CIDR: " ip || exit 0
    case $a in
      1) $0 ban "$ip" ;;
      2) $0 unban "$ip" ;;
      3) $0 allow "$ip" ;;
      4) $0 unallow "$ip" ;;
      5) $0 check "$ip" ;;
    esac
  done
}

menu() {
  while true; do
    clear
    n=$(ipset list $SET -t 2>/dev/null | awk '/Number of entries/{print $4}')
    d=$(iptables -nvxL $CH 2>/dev/null | awk '$3=="DROP"{print $1; exit}')
    printf '\n  RKNPIDOR MANAGER\n  --------------------------\n'
    printf '  Подсетей:        %s\n  Пакетов отбито:  %s\n\n' "${n:-0}" "${d:-0}"
    echo "  1. Топ атак (CSV)"
    echo "  2. Логи (Live)"
    echo "  3. Управление IP (Ban/Unban/Allow)"
    echo "  4. Обновить списки (Update)"
    echo "  5. Переустановить (Reinstall)"
    echo "  6. Удалить (Uninstall)"
    echo "  0. Выход"
    echo
    read -rp "Ваш выбор: " c || exit 0
    case $c in
      1) top 20; pause ;;
      2) journalctl -kf --no-pager | grep --line-buffered 'RKNP:' ;;
      3) ipmenu ;;
      4) $0 update; pause ;;
      5) curl -fsSL "$SELF_URL" | bash; pause ;;
      6) read -rp "Удалить? [y/N]: " y || exit 0
         [ "$y" = y ] && { $0 uninstall; exit 0; } ;;
      0) exit 0 ;;
    esac
  done
}

case "${1:-menu}" in
  menu)    menu ;;
  top)     top "${2:-20}" ;;
  update)  fetch && load && rules && echo "ok: $(wc -l < $DATA/list.txt) записей" ;;
  boot)    [ -s $DATA/list.txt ] || fetch; load; rules ;;
  on)      load; rules ;;
  off)     unrules ;;
  status)
    ipset list $SET -t 2>/dev/null | grep -E 'Number of entries' || echo "set не загружен"
    iptables -nvL $CH 2>/dev/null || echo "правила выключены"
    ;;
  ban)     [ -n "${2:-}" ] || exit 1
           echo "$2" >> $CONF/blacklist.txt; ipset add $SET "$2" -exist; echo "ban $2" ;;
  unban)   [ -n "${2:-}" ] || exit 1
           sed -i "\|^$2\$|d" $CONF/blacklist.txt; ipset del $SET "$2" 2>/dev/null; echo "unban $2" ;;
  allow)   [ -n "${2:-}" ] || exit 1
           echo "$2" >> $CONF/whitelist.txt; ipset add $WL "$2" -exist; echo "allow $2" ;;
  unallow) [ -n "${2:-}" ] || exit 1
           sed -i "\|^$2\$|d" $CONF/whitelist.txt; ipset del $WL "$2" 2>/dev/null; echo "unallow $2" ;;
  check)   [ -n "${2:-}" ] || exit 1
           ipset test $SET "$2" 2>&1 ;;
  logs)    journalctl -k --no-pager | grep 'RKNP:' | tail -${2:-50} ;;
  uninstall)
    unrules
    systemctl disable --now rknpidor.timer rknpidor.service 2>/dev/null
    rm -f /etc/systemd/system/rknpidor.{service,timer} /etc/systemd/system/rknpidor-update.service
    systemctl daemon-reload
    ipset destroy $SET 2>/dev/null; ipset destroy $WL 2>/dev/null
    rm -rf $CONF $DATA /usr/local/bin/rknpidor
    echo "удалено"
    ;;
  *) echo "rknpidor [menu|status|update|on|off|ban IP|unban IP|allow IP|unallow IP|check IP|top [N]|logs [N]|uninstall]" ;;
esac
EOF
chmod +x /usr/local/bin/rknpidor

cat > /etc/systemd/system/rknpidor.service <<'EOF'
[Unit]
Description=rknpidor ipset blocklist
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/rknpidor boot
ExecStop=/usr/local/bin/rknpidor off

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

cat > /etc/systemd/system/rknpidor.timer <<'EOF'
[Unit]
Description=rknpidor daily update

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=1800
Persistent=true
Unit=rknpidor-update.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
/usr/local/bin/rknpidor update
systemctl enable rknpidor.service rknpidor.timer
systemctl start rknpidor.timer
echo "готово: rknpidor"