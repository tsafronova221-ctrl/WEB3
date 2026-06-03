#!/bin/bash
# Развёртывание топологии лабораторной сети PIM
# ALT Linux 11 p11 — протестировано на ядре 6.6.x
set -euo pipefail

# ── 1. Очистка предыдущего состояния ──────────────────────────
echo "[*] Очистка предыдущих пространств имён..."
for NS in R1 R2 R3 R4 Source Receiver Attacker; do
    ip netns del "$NS" 2>/dev/null && echo "  удалён: $NS" || true
done

# ── 2. Создание пространств имён сети ─────────────────────────
echo "[*] Создание пространств имён..."
for NS in R1 R2 R3 R4 Source Receiver Attacker; do
    ip netns add "$NS"
    # Включить loopback в каждом пространстве имён
    ip netns exec "$NS" ip link set lo up
done

# ── 3. Вспомогательная функция: создание veth-пары ───────────
mk_link() {
    local ns1=$1 if1=$2 ip1=$3 ns2=$4 if2=$5 ip2=$6
    ip link add "$if1" netns "$ns1" type veth peer name "$if2" netns "$ns2"
    ip netns exec "$ns1" ip addr add "$ip1" dev "$if1"
    ip netns exec "$ns2" ip addr add "$ip2" dev "$if2"
    ip netns exec "$ns1" ip link set "$if1" up
    ip netns exec "$ns2" ip link set "$if2" up
}

# ── 4. Source-сегмент: R1 + Source + Attacker в одном L2 ─────
# Создаём мост br-src в пространстве имён R1
ip netns exec R1 ip link add br-src type bridge
ip netns exec R1 ip addr add 10.1.1.1/24 dev br-src
ip netns exec R1 ip link set br-src up

# Подключаем Source к мосту
ip link add veth-r1-src netns R1 type veth peer name eth0 netns Source
ip netns exec R1 ip link set veth-r1-src master br-src
ip netns exec R1 ip link set veth-r1-src up
ip netns exec Source ip addr add 10.1.1.100/24 dev eth0
ip netns exec Source ip link set eth0 up
ip netns exec Source ip route add default via 10.1.1.1

# Подключаем Attacker к мосту
ip link add veth-r1-att netns R1 type veth peer name eth0 netns Attacker
ip netns exec R1 ip link set veth-r1-att master br-src
ip netns exec R1 ip link set veth-r1-att up
ip netns exec Attacker ip addr add 10.1.1.200/24 dev eth0
ip netns exec Attacker ip link set eth0 up
ip netns exec Attacker ip route add default via 10.1.1.1

# ── 5. Транзитные сегменты между маршрутизаторами ────────────
mk_link R1 eth-r2 10.1.12.1/30  R2 eth-r1 10.1.12.2/30
mk_link R2 eth-r3 10.2.23.1/30  R3 eth-r2 10.2.23.2/30
mk_link R3 eth-r4 10.3.34.1/30  R4 eth-r3 10.3.34.2/30

# ── 6. Receiver-сегмент ──────────────────────────────────────
mk_link R4 eth-rcv 10.5.0.1/24  Receiver eth0 10.5.0.100/24
ip netns exec Receiver ip route add default via 10.5.0.1

# ── 7. Loopback-адреса маршрутизаторов ──────────────────────
ip netns exec R1 ip addr add 10.0.0.1/32 dev lo
ip netns exec R2 ip addr add 10.0.0.2/32 dev lo
ip netns exec R3 ip addr add 10.0.0.3/32 dev lo
ip netns exec R4 ip addr add 10.0.0.4/32 dev lo

# ── 8. IP-форвардинг в маршрутизаторах ──────────────────────
for R in R1 R2 R3 R4; do
    ip netns exec "$R" sysctl -w net.ipv4.ip_forward=1 > /dev/null
    ip netns exec "$R" sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null
done

echo "[OK] Топология развёрнута успешно."
echo "     Следующий шаг: запустите 02_start_frr.sh"
