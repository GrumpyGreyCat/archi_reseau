## Pentest KingsGuard

#### Round 1 - Red Team

``` bash
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:00:00:04:00 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.100/24 brd 10.0.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:ff:fe00:400/64 scope link proto kernel_ll 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:00:00:04:01 brd ff:ff:ff:ff:ff:ff
    inet 172.30.42.10/24 brd 172.30.42.255 scope global dynamic noprefixroute eth1
       valid_lft 2424985sec preferred_lft 2100985sec
    inet6 fe80::e345:f53b:a77c:bac3/64 scope link 
       valid_lft forever preferred_lft forever
```

```bash 
nmap -sS -Pn -p 22,53,80,443 --max-retries 2 --max-parallelism 10 10.0.0.100 
Starting Nmap 7.95 ( https://nmap.org/ ) at 2026-05-04 04:34 EDT
Nmap scan report for 10.0.0.100
Host is up (0.00030s latency).

PORT    STATE  SERVICE
22/tcp  open   ssh
53/tcp  closed domain
80/tcp  closed http
443/tcp closed https

Nmap done: 1 IP address (1 host up) scanned in 13.16 seconds
```

```bash
nmap -sS -sV -Pn -p 22,53,80,443 --max-retries 2 --max-parallelism 10 -T3 172.30.0.0
Starting Nmap 7.95 ( https://nmap.org/ ) at 2026-05-04 05:18 EDT
Nmap scan report for 172.30.0.0
Host is up.

PORT    STATE    SERVICE VERSION
22/tcp  filtered ssh
53/tcp  filtered domain
80/tcp  filtered http
443/tcp filtered https

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.32 seconds
```