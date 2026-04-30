---
layout: post
title: Balanceamento de carga usando Iptables e Squid
date: 2015-09-24 21:03:39.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/balanceamento-de-carga-usando-iptables-e-squid/"
---

Após muita pesquisa em fóruns on-line, bem como muitas configurações erradas, muitos cabelos perdidos, estou trazendo a você um passo-a-passo para configurar o Iptables e Squid para possibilitar o balanceamento de carga utilizando uma única instancia (instalação) do Squid e Iptables.

O balanceamento de carga, neste nosso ambiente, tem o objetivo de possibilidar que você tenha 2 ou mais provedores de acesso a internet (ex.: ADSL, Cable, etc...) balanceanco o seu tráfego de rede balanceado entre eles.

<!--more-->![Mais...]({{ site.baseurl }}/assets/2015/09/trans.gif)

## Preparação do ambiente

Para este passo-a-passo utilizei como distribuição linux o Ubuntu 14.04.

O primeiro passo, em qualquer instalação de servidor ao meu ver, é garantir que todos os pacotes básicos estejam devidamente atualizados.

```bash
apt-get update;
apt-get upgrade;
```

Na sequência vamos instalar os pacotes básicos para nosso ambiente.

```bash
apt-get install iptables squid iproute
```

## Ambiente

Para  o correto entendimento de todo o procedimento e objetivo nada melhor que visualizarmos o ambiente gráficamente, e as configurações iniciais. Na imagem abaixo pode-se visualizar que temos 3 links de internet, que chamamos de ISP (do inglês Internet Service provider, que significa provedor de acesso a internet). Este ISP pode ser qualquer provedor de acesso a internet como GVT, NET, Oi, Copel e etc... e cada um utilizando sua tecnologia como ADSL, Cabo, Fibra e etc.

[![Lab Balanceamento]({{ site.baseurl }}/assets/2015/09/Lab-Balanceamento.png)]({{ site.baseurl }}/assets/2015/09/Lab-Balanceamento.png)

Segue abaixo o arquivo da configuração das placas de rede (**/etc/network/interfaces**)

```bash
# The loopback network interface
auto lo
iface lo inet loopback

# Interface ligada ao ISP1
auto eth0
iface eth0 inet static
address 192.168.50.4
netmask 255.255.255.0
gateway 192.168.50.1

# Interface ligada ao ISP2
auto eth1
iface eth1 inet static
address 192.168.60.4
netmask 255.255.255.0

# Interface ligada ao ISP3
auto eth2
iface eth2 inet static
address 192.168.70.4
netmask 255.255.255.0

# Interface da minha rede interna
auto eth3
iface eth3 inet static
address 192.168.254.101
netmask 255.255.255.0
```

## Configurando o Squid

A configuração do squid baseia-se no artigo do blog Tasty Placement disponível neste link ([https://www.tastyplacement.com/squid-proxy-multiple-outgoing-ip-addresses](https://www.tastyplacement.com/squid-proxy-multiple-outgoing-ip-addresses)). Basicamente a configuração deve ocorrer no arquivo **/etc/squid3/squid.conf** usando as sequintes diretivas:

- http_port
- name=
- myportname
- acl
- http_access
- tcp_outgoing_address

Primeiramente necessitamos definir quais portas o Squid realizará escuta, estas portas serão utilizadas para posteriormente definirmos por qual link este tráfego de rede deverá sair, em outras palavras, cada porta que o Squid receber uma requisição estará atrelada a um link de acesso a internet. Segue a configuração:

```bash
http_port 3128 transparent name=isp1
http_port 3129 transparent name=isp2
http_port 3130 transparent name=isp3
```

Nestas configurações acima habilitamos o squid para escutar nas portas (3128, 3129 e 3130), e definimos um nome para cada uma dessas portas (isp1, isp2 e isp3). Agora iremos criar as regras (ACL) baseando-se nessas portas para definir por qual ISP será a saída do trafego.

```bash
acl acl_isp1 myportname isp1
acl acl_isp2 myportname isp2
acl acl_isp3 myportname isp3

tcp_outgoing_address 192.168.50.4 acl_isp1
tcp_outgoing_address 192.168.60.4 acl_isp2
tcp_outgoing_address 192.168.70.4 acl_isp3
```

Agora que vimos as principais personalizações necessárias no squid segue abaixo meu arquivo **/etc/squid3/squid.conf** completo

```bash
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1

access_log /var/log/squid3/access.log squid

visible_hostname seudominio.com.br
cache_mgr email@seudominio.com.br

acl SSL_ports port 443
acl Safe_ports port 80 # http
acl Safe_ports port 21 # ftp
acl Safe_ports port 443 # https
acl Safe_ports port 70 # gopher
acl Safe_ports port 210 # wais
acl Safe_ports port 1025-65535 # unregistered ports
acl Safe_ports port 280 # http-mgmt
acl Safe_ports port 488 # gss-http
acl Safe_ports port 591 # filemaker
acl Safe_ports port 777 # multiling http
acl CONNECT method CONNECT

acl rede_interna src 192.168.0.0/255.255.0.0

http_access allow manager localhost
http_access deny manager
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost
http_access allow rede_interna
http_access deny all

#Configuração das portas por link de saída
http_port 3128 transparent name=isp1
http_port 3129 transparent name=isp2
http_port 3130 transparent name=isp3

acl acl_isp1 myportname isp1
acl acl_isp2 myportname isp2
acl acl_isp3 myportname isp3

tcp_outgoing_address 192.168.50.4 acl_isp1
tcp_outgoing_address 192.168.60.4 acl_isp2
tcp_outgoing_address 192.168.70.4 acl_isp3

coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern (Release|Packages(.gz)*)$ 0 20% 2880
refresh_pattern . 0 20% 4320
quick_abort_max 16 KB
quick_abort_pct 95
quick_abort_min 16 KB
request_header_max_size 20 KB
reply_header_max_size 20 KB
request_body_max_size 0 KB

cache_mem 1024 MB

cache_log /var/log/squid3/cache.log
cache_access_log none
cache_store_log none
```

## Configurando IPTables

Para efeitos de aprendizado o processo de configuração será realizado em 2 etapas, na primeira iremos fazer o que é exclusivo para o funcionamento do Squid (realização de proxy transparente, ou seja, encaminhamento das conexões HTTP), na segunda fase incluiremos a configuração para o balanceamento das outras conexões de rede (E-mail, Torrent, etc...)

### Fase 1

Para o correto funcionamento do balanceamento de link precisaremos definir os roteadores padrão (Default Gateway) de cada um dos links conforme demonstrado abaixo:

**Configuração para o ISP1**

```bash
ip route flush table 5
ip rule add fwmark 5 table 5
ip rule add from 192.168.50.0/24 table 5
ip rule add to 192.168.50.0/24 table 5
ip route add table 5 default via 192.168.50.1
```

**Configuração para o ISP2**

```bash
ip route flush table 6
 ip rule add fwmark 6 table 6
 ip rule add from 192.168.60.0/24 table 6
 ip rule add to 192.168.60.0/24 table 6
 ip route add table 6 default via 192.168.60.1
```

**Configuração para o ISP3**

```bash
ip route flush table 7
 ip rule add fwmark 7 table 7
 ip rule add from 192.168.70.0/24 table 7
 ip rule add to 192.168.70.0/24 table 7
 ip route add table 7 default via 192.168.70.1
```

Com essas configurações acima definimos qual o gateway de saída de cada um dos links bem como a rede de operação. Este gateway deve ser o endereço IP do modem da sua operadora.

Com isso basta direcionar os pacotes de acesso web para o squid utilizando os compandos iptables abaixo

```bash
iptables -t nat -A PREROUTING -s 192.168.254.0/24 -p TCP -m statistic --mode random --probability 0.33 -m multiport --dports 80,8080 -j REDIRECT --to-port 3129
iptables -t nat -A PREROUTING -s 192.168.254.0/24 -p TCP -m statistic --mode random --probability 0.33 -m multiport --dports 80,8080 -j REDIRECT --to-port 3130
iptables -t nat -A PREROUTING -s 192.168.254.0/24 -p TCP -m multiport --dports 80,8080 -j REDIRECT --to-port 3128
```

O segredo do balanceamento está na forma e na ordem de execução destes comandos. Estes comandos tem 2 informações importantes que merecem um pouco mais de atenção:

1. **-m statistic --mode random --probability 0.33** este trecho do comando indica que essa regra será aplicada de forma randômica a uma média de 33% dos acessos web;
2. **REDIRECT --to-port XXXX** este trecho redireciona o pacote para a respectiva porta do Squid.

Sendo assim podemos observar que as 2 primeiras regras seguem o padrão de probablilidade de 33% para cada uma, e caso nenhuma dassas 2 regras tratem o trafego web, cairá na regra padrão que é a terceira regra.

### Fase 2

Neste fase finalizaremos a configuração do iptables para realizar o balanceamento do restante do trafego web (E-mail, Torrent, etc...). Este processo é um pouco mais complicado pois não podemos somente marcar os pacotes aleatoriamente, mas sim marcar a conexão como um todo e garantir que durante toda essa conexão a mesma saia pelo link inicialmente marcado.

Desta forma para este processo criaremos uma cadeia (Chain) no iptables, depois encaminharemos para esa cadeia somente os pacotes de novas conexões, a cadeia responsável por este processo é a **balance1**. Adicionalmente é necessário a cada novo pacote da mesma conexão identificar a marcação inicial, este segundo processo fica a cargo da cadeia **RESTOREMARK.**

Abaixo segue o script completo do iptables.

### Script iptables final

Segue abaixo o script final do iptables, este conteúdo deve ser salvo no arquivo **/etc/init.d/firewall**

```bash
#!/bin/bash
#

if [ ! -x /sbin/iptables ]; then
exit 0
fi
# criar este arquivo como /etc/init.d/firewall
# Executar o comando abaixo para definir script como inicializavel
# chmod +x /etc/init.d/firewall
# sudo update-rc.d -f firewall defaults
# Comandos
IPTABLES=/sbin/iptables
IFCONFIG=/sbin/ifconfig
ROUTE=/sbin/route
IP=/bin/ip

start()
 {
 # clear all
 clearall

# Limpa as regras atuais
 $IPTABLES -F
 $IPTABLES -X
 $IPTABLES -t nat -F
 $IPTABLES -t nat -X
 $IPTABLES -t mangle -F
 $IPTABLES -t mangle -X
 $IPTABLES --flush

# Regra padrão (Bloqueia tudo)
 $IPTABLES -P INPUT ACCEPT
 $IPTABLES -P OUTPUT ACCEPT
 $IPTABLES -P FORWARD ACCEPT

# Libera os retornos de stados e pacotes de saida
 $IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
 $IPTABLES -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
 $IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Liberando tudo da Loopback
 $IPTABLES -A INPUT -i lo -j ACCEPT

# Libera forward e adiciona as rotas
echo 1 > /proc/sys/net/ipv4/ip_forward
for f in /proc/sys/net/ipv4/conf/*/rp_filter ; do echo 0 > $f ; done
echo 0 > /proc/sys/net/ipv4/route/flush

# Indica para rebotar após 1 segundos em caso de kernel panic
echo 1 > /proc/sys/kernel/panic

# Carrega módulos para FTP
 modprobe ip_nat_ftp
 modprobe nf_conntrack_ftp
 modprobe ip_conntrack_netlink

# Variaveis globais de definições
 internal_net=192.168.254.0/24

isp1_net=192.168.50.0/24
isp1_table=5
isp1_gw=192.168.50.1
isp1_weight=1

isp2_net=192.168.60.0/24
isp2_table=6
isp2_gw=192.168.60.1
isp2_weight=1

isp3_net=192.168.70.0/24
isp3_table=7
isp3_gw=192.168.70.1
isp3_weight=1

 # Rotas e marcações para link 1
 $IP rule del fwmark $isp1_table table $isp1_table 2>/dev/null
 $IP rule del from $isp1_net table $isp1_table 2>/dev/null
 $IP rule del to $isp1_net table $isp1_table 2>/dev/null
 $IP route del table $isp1_table default via $isp1_gw  2>/dev/null
 $IP route flush table $isp1_table
 $IP rule add fwmark $isp1_table table $isp1_table
 $IP rule add from $isp1_net table $isp1_table
 $IP rule add to $isp1_net table $isp1_table
 $IP route add table $isp1_table default via $isp1_gw

# Rotas e marcações para link 2
 $IP rule del fwmark $isp2_table table $isp2_table 2>/dev/null
 $IP rule del from $isp2_net table $isp2_table 2>/dev/null
 $IP rule del to $isp2_net table $isp2_table 2>/dev/null
 $IP route del table $isp2_table default via $isp2_gw 2>/dev/null
 $IP route flush table $isp2_table
 $IP rule add fwmark $isp2_table table $isp2_table
 $IP rule add from $isp2_net table $isp2_table
 $IP rule add to $isp2_net table $isp2_table
 $IP route add table $isp2_table default via $isp2_gw

# Rotas e marcações para link 3
 $IP rule del fwmark $isp3_table table $isp3_table 2>/dev/null
 $IP rule del from $isp3_net table $isp3_table 2>/dev/null
 $IP rule del to $isp3_net table $isp3_table 2>/dev/null
 $IP route del table $isp3_table default via $isp3_gw 2>/dev/null
 $IP route flush table $isp3_table
 $IP rule add fwmark $isp3_table table $isp3_table
 $IP rule add from $isp3_net table $isp3_table
 $IP rule add to $isp3_net table $isp3_table
 $IP route add table $isp3_table default via $isp3_gw

# Restaura a mesma marcacao para os pacotes saintes
$IPTABLES -t mangle -N RESTOREMARK
$IPTABLES -t mangle -A RESTOREMARK -d $isp1_net -j RETURN
$IPTABLES -t mangle -A RESTOREMARK -d $isp2_net -j RETURN
$IPTABLES -t mangle -A RESTOREMARK -d $isp3_net -j RETURN
$IPTABLES -t mangle -A RESTOREMARK -j CONNMARK  --restore-mark
$IPTABLES -t mangle -A PREROUTING -m state --state ESTABLISHED,RELATED -j RESTOREMARK

# Regra de balanceamento (Divite 33% para cada link)
$IPTABLES -t mangle -F balance1 >/dev/null 2>&1 # flush balance1 if exists
$IPTABLES -t mangle -X balance1 >/dev/null 2>&1 # delete balance1 if exists
$IPTABLES -t mangle -N balance1
$IPTABLES -t mangle -A balance1 -d $internal_net -j RETURN
$IPTABLES -t mangle -A balance1 -m connmark ! --mark 0 -j RETURN
$IPTABLES -t mangle -A balance1 -m state --state ESTABLISHED,RELATED -j RETURN
$IPTABLES -t mangle -A balance1 -m statistic --mode nth --every 3 --packet 0 -j CONNMARK --set-mark $isp1_table
$IPTABLES -t mangle -A balance1 -m statistic --mode nth --every 3 --packet 1 -j CONNMARK --set-mark $isp2_table
$IPTABLES -t mangle -A balance1 -m statistic --mode nth --every 3 --packet 2 -j CONNMARK --set-mark $isp3_table
$IPTABLES -t mangle -A balance1 -m connmark --mark 0 -j CONNMARK --set-mark $isp1_table
$IPTABLES -t mangle -A balance1 -m connmark --mark $isp1_table -j MARK --set-mark $isp1_table
$IPTABLES -t mangle -A balance1 -m connmark --mark $isp2_table -j MARK --set-mark $isp2_table
$IPTABLES -t mangle -A balance1 -m connmark --mark $isp3_table -j MARK --set-mark $isp3_table
$IPTABLES -t mangle -A balance1 -m connmark ! --mark 0  -j CONNMARK --save-mark

# Encaminha as novas conexoes para o Balancer
$IPTABLES  -t mangle -A PREROUTING -s $internal_net -m state --state NEW -j balance1

# Caso deseje, habilite essa regra para efetuar log dos pacotes com marcação
#$IPTABLES -t mangle -A FORWARD -m connmark ! --mark 0 -j LOG --log-prefix 'FORWARD Marked: ' --log-level info

 # Comandos para direcionamento balanceado ao Squid
 $IPTABLES -t nat -A PREROUTING -s $internal_net -p TCP -m statistic --mode random --probability 0.33 -m multiport --dports 80,8080 -j REDIRECT --to-port 3129
 $IPTABLES -t nat -A PREROUTING -s $internal_net -p TCP -m statistic --mode random --probability 0.33 -m multiport --dports 80,8080 -j REDIRECT --to-port 3130
 $IPTABLES -t nat -A PREROUTING -s $internal_net -p TCP -m multiport --dports 80,8080 -j REDIRECT --to-port 3128

# Regras de NAT
 $IPTABLES -t nat -A POSTROUTING -o eth0 -j MASQUERADE
 $IPTABLES -t nat -A POSTROUTING -o eth1 -j MASQUERADE
 $IPTABLES -t nat -A POSTROUTING -o eth2 -j MASQUERADE

$IP route flush cache
}

clearall()
 {
 $IPTABLES -F
 $IPTABLES -X
 $IPTABLES -t nat -F
 $IPTABLES -t nat -X
 $IPTABLES -t mangle -F
 $IPTABLES -t mangle -X
 $IPTABLES --flush

# Regra padrão (Libera tudo)
 $IPTABLES -P INPUT ACCEPT
 $IPTABLES -P OUTPUT ACCEPT
 $IPTABLES -P FORWARD DROP

$IP route flush table 5
 $IP route flush table 6
 $IP route flush table 7
 $IP route flush cache

}

case "$1" in
 restart|start)
 start
 ;;
 stop)
 clearall
 ;;
 *)
 echo "Usage: $0 {start|stop|restart}"
 exit 1
 esac

exit 0
```

Para que este script se execute automaticamente no inicio do sistema operacional execute os comandos abaixo

```bash
chmod +x /etc/init.d/firewall
sudo update-rc.d -f firewall defaults
```

## Extras

Caso você precise realizar um balanceamento do link com base em peso, ou seja, um link tem maior capacidade que o outro e você quer balancear a carga conforme a capacidade do link, você pode utilizar a metodologia proposta nest [link](https://home.regit.org/netfilter-en/links-load-balancing/), que explicarei de forma breve aqui.

Vamos supor que você tem 2 links e um deles e eles seguem a seguinte fração 1/4 e 3/4, desta forma iremos marcar os pacotes de forma a usar um contador de 4 distribuindo da seguinte forma

1. Marca o pacote para o **primeiro** link
2. Marca o pacote para o **segundo** link
3. Marca o pacote para o **primeiro** link
4. Marca o pacote para o **primeiro** link

Basicamente as regras do iptables para implantar essa lógica ficará assim:

```bash
iptables -A PREROUTING  -t mangle -m mark --mark 0x0 -m statistic --mode nth --every 4 --packet 0 -j MARK --set-mark 1
iptables -A PREROUTING  -t mangle -m mark --mark 0x0 -m statistic --mode nth --every 4 --packet 1 -j MARK --set-mark 2
iptables -A PREROUTING  -t mangle -m mark --mark 0x0 -m statistic --mode nth --every 4 --packet 2 -j MARK --set-mark 1
iptables -A PREROUTING  -t mangle -m mark --mark 0x0 -m statistic --mode nth --every 4 --packet 3 -j MARK --set-mark 1
```
