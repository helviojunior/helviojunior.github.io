---
layout: post
title: Estabelecendo VPN Site-to-site IPSEC com OpenSwan
date: 2014-10-29 23:54:57.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Linux
- Segurança da Informação
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/estabelecendo-vpn-site-to-site-ipsec-natt-openswan/"
---

﻿Neste post veremos passo a passo como configurar o OpenSwan para estabelecer uma VPN Site-to-site (entre 2 redes)  utilizando segredo compartilhado ou certificado digital. No decorrer do post explicarei as diferenças quando um dos firewall está atrás de um equipamento realizando NAT-T.

A motivação da escrita deste post se deu na necessidade de realizar essa VPN em meu ambiente somado ao fato que não encontrei na internet nenhum tutorial que trouxesse de forma simples, completa e bem comentada cada um dos parâmetros para o correto funcionamento do OpenSwan no ambiente proposto. Achei sim, diversos tutoriais, que me ajudaram muito, mas somente informações fragmentadas e muitas vezes confusas, sendo assim resolvi agregar todas em um único post. Espero que ajude.

<!--more-->

## Ambiente

Antes de iniciar a configuração propriamente dita do OpenSwan e dos equipamentos é necessário entender bem todo o nosso ambiente.

Antes de mais nada é importante frisar que os IPs validos e inválidos deste ambiente são fictícios e escolhidos aleatoriamente, não representando qualquer ambiente real meu ou de cliente.

Para os dois servidores de VPN foi utilizado o Ubuntu 12.0.4, e o OpenSwan do repositório do ubuntu.

Esta imagem abaixo demonstra detalhadamente todo o nosso ambiente.

[![Ambiente VPN site to site]({{ site.baseurl }}/assets/2014/10/Lab.png)]({{ site.baseurl }}/assets/2014/10/Lab.png)

Nela podemos observar que há 2 servidores de VPN, um na matriz e um na filial, e que o servidor da filial está atrás de um Roteador que está fazendo NAT. Este é um ambiente bem comum quando a filial está utilizando uma internet de baixo custo onde a operadora fornece o modem (como por exemplo ADSL) e este modem é quem recebe o IP válido e distribui uma rede inválida (comumente 192.168.x.x) para as maquinas internas.

## Configuração de rede dos servidores de VPN

Segue abaixo a configuração de rede de cada um dos servidores VPN

[caption id="attachment_1074" align="alignnone" width="405"][![metwork-matriz]({{ site.baseurl }}/assets/2014/10/metwork-matriz.png)]({{ site.baseurl }}/assets/2014/10/metwork-matriz.png) Configuração de rede do servidor de VPN da Matriz[/caption]

[caption id="attachment_1075" align="alignnone" width="405"][![network-filial]({{ site.baseurl }}/assets/2014/10/network-filial.png)]({{ site.baseurl }}/assets/2014/10/network-filial.png) Configuração de rede do servidor de VPN da Filial[/caption]

## Instalando OpenSwan

O processo de instalação do OpenSwan é o mesmo para os dois equipamentos, desta forma execute os passos abaixo nos 2.

Instalando o OpenSwan e OpenSSL

```bash
add-apt-repository ppa:openswan/ppa
apt-get update
apt-get install openssl openswan
```

Neste processo será questionado se deseja criar um certificado digital para este servidor. Pode selecionar a opção **<NO>**

[![openswan-01]({{ site.baseurl }}/assets/2014/10/openswan-01.png)]({{ site.baseurl }}/assets/2014/10/openswan-01.png)

Edite o arquivo **/etc/ipsec.conf** (em ambos equipamentos) para que ele fique com o seguinte conteúdo:

```bash
version 2.0
config setup
        dumpdir=/var/run/pluto/
        nat_traversal=yes
        virtual_private=%v4:10.0.0.0/8
        oe=off
        protostack=netkey

conn %default
        authby=rsasig
        leftrsasigkey=%cert
        rightrsasigkey=%cert
        keyingtries=1
        keylife=20m
        ikelifetime=240m

include /etc/ipsec.d/*.conf
```

Edite o arquivo **/etc/ipsec.secrets** para que ele fique com o seguinte conteúdo:

```bash
include /var/lib/openswan/ipsec.secrets.inc
include /etc/ipsec.d/*.secret
```

Edite o arquivo **/etc/sysctl.conf** e altere ou insira a seguinte linha. Esta configuração tem por objetivo permitir que o kernel do linux faça roteamento dos pacotes de rede.

```bash
net.ipv4.ip_forward = 1
```

E depois execute o seguinte comando para aplicar essa configuração:

```bash
sysctl -p
```

Pronto as configurações gerais estão prontas, agora vamos para as configurações individuais de cada servidor de VPN.

### Um pouco sobre segredo compartilhado *versus* certificado digital

Quando estamos configurando uma VPN com IPSEC há diversos fatores que podem influenciar e gerar problema no estabelecimento da conexão, desta forma sempre iniciamos a configuração de forma simples, e depois vamos incrementando opções e segurança. Seguindo esta lógica primeiro iremos configurar e estabelecer o tunnel VPN utilizando segredo compartilhado, para depois que o tunnel tiver OK possamos trocar para certificado digital.

Mas porque isso? Porque com certificado digital há diversos outros fatores que podem gerar problema como data de validade do certificado, common name, tipo do certificado, autoridade certificadora entre outros, então a forma mais simples de isolar os problemas é primeiro estabelecer o tunnel usando segredo compartilhado.

Por característica do protocolo IPSEC, para estabelecer um tunnel com segrede compartilhado é necessário saber o IP interno e externo de todos os envolvidos, não podendo ser nenhum dos 2 lados dinâmico, desta forma se em eu ambiente você utiliza uma internet com IP dinâmico, para estes primeiros passos descubra qual é o IP atualmente atribuido, faça a configuração com ele que nos próximos passos (depois de mudar o tunnel para usar certificado digital) iremos alterar para não precisar informar este IP na configuração.

### VPN Server Matriz

Nesta sessão veremos todas as configurações que devem serem realizadas no servidor de VPN da matriz.

Crie um arquivo nomeado **/etc/ipsec.d/vpn1.conf** e insira o seguinte conteúdo:

```bash
conn vpn1 # Nome da Conexão VPN
	type= tunnel
	authby= secret #Tipo de autenticação

	# Left security, (dados da Matriz)
	left= 200.165.10.50 # IP real/físico do servidor na matriz
	leftsubnet= 10.0.0.0/24 # Rede interna na Matriz para qual será estabelecido a VPN
	leftnexthop= 200.165.10.1 # IP real do Gateway do servidor de VPN da Matriz

	# Right security, (dados da Filial)
	right= 201.80.24.7 # IP Externo (após o NAT) que o servidor sairá para conexão com a matriz
	rightsubnet= 10.0.1.0/24 # Rede interna da filial para qual será estabelecido a VPN
	rightnexthop= 200.165.10.1 # IP real do Gateway do servidor de VPN da Matriz

	# Tipo de criptografia usada
	keyexchange=ike

	# IPSEC Fase 1
	# Não é obrigatório o preenchimento, caso preenchido será restrito a estes protocolos preenchidos
	# Formato de preenchimento 'cipher-hash;modpgroup, cipher-hash;modpgroup, ...'
	#   -> Não é obrigatório o preenchimento do modpgroup
	# cipher-hash disponíveis: 3des-sha1, 3des-md5, aes-sha1, aes-md5, aes128-sha1 e aes128-md5
	# modpgroup disponíveis: modp1024, modp1536 e modp2048
	ike= 3des-md5, 3des-sha1,aes-sha1,aes-md5,aes128-sha1,aes128-md5

	# IPSEC Fase 2
	# cipher-hash disponíveis: 3des, 3des-md5-96, 3des-sha1-96
	phase2alg = 3des-md5-96 # Antigo parametro 'esp' que está obsoleto

	# Outras configurações
	pfs= no
	auto= start
```

Agora crie o arquivo nomeado **/etc/ipsec.d/vpn1.secret** com o seguinte conteúdo

```bash
201.80.24.7 200.165.10.50: PSK "123456"
```

Agora reinicie o serviço do ipsec com o seguinte comando

```bash
ipsec setup restart
```

Caso deseje reiniciar somente um tunnel utilize os comandos abaixo

```bash
ipsec auto --down vpn1
ipsec auto --up vpn1
```

### VPN Server Filial

Nesta sessão veremos todas as configurações que devem serem realizadas no servidor de VPN da filial.

Crie um arquivo nomeado **/etc/ipsec.d/vpn1.conf** e insira o seguinte conteúdo:

```bash
conn vpn1 # Nome da Conexão VPN
	type= tunnel
	authby= secret #Tipo de autenticação

	# Left security, (dados da Filial)
	left= 192.168.0.10 # IP real/físico do servidor na filial
	leftid= 201.80.24.7 # IP Externo (após o NAT) que o servidor sairá para conexão com a matriz
	leftsubnet= 10.0.1.0/24 # Rede interna na filial para qual será estabelecido a VPN
	leftnexthop= 192.168.0.1 # IP real do Gateway do servidor de VPN da filial

	# Right security, (dados da Matriz)
	right= 200.165.10.50 # IP externo do servidor na matriz
	rightsubnet= 10.0.0.0/24 # Rede interna da matriz para qual será estabelecido a VPN
	rightnexthop= 192.168.0.1 # IP real do Gateway do servidor de VPN da filial

	# Tipo de criptografia usada
	keyexchange=ike

	# IPSEC Fase 1
	# Não é obrigatório o preenchimento, caso preenchido será restrito a estes protocolos preenchidos
	# Formato de preenchimento 'cipher-hash;modpgroup, cipher-hash;modpgroup, ...'
	#   -> Não é obrigatório o preenchimento do modpgroup
	# cipher-hash disponíveis: 3des-sha1, 3des-md5, aes-sha1, aes-md5, aes128-sha1 e aes128-md5
	# modpgroup disponíveis: modp1024, modp1536 e modp2048
	ike= 3des-md5, 3des-sha1,aes-sha1,aes-md5,aes128-sha1,aes128-md5

	# IPSEC Fase 2
	# cipher-hash disponíveis: 3des, 3des-md5-96, 3des-sha1-96
	phase2alg = 3des-md5-96 # Antigo parametro 'esp' que está obsoleto

	# Outras configurações
	pfs= no
	auto= start
```

Agora crie o arquivo nomeado **/etc/ipsec.d/vpn1.secret** com o seguinte conteúdo

```bash
200.165.10.50 201.80.24.7: PSK "123456"
```

Agora reinicie o serviço do ipsec com o seguinte comando

```bash
ipsec setup restart
```

Caso deseje reiniciar somente um tunnel utilize os comandos abaixo

```bash
ipsec auto --down vpn1
ipsec auto --up vpn1
```

### Verificando status e erros de configuração

Após iniciar a configuração alguns passos podem ser feito para checar a configuração e correto carregamento da mesma, bem como erros no estabelecimento do tunnel.

Verifique no arquivo de log **/var/log/auth.log** se estes 2 logs foram gerados, eles indicam que o arquivo de chaves da VPN foi carregado e que a vpn1 foi carregada e será iniciado o processo para estabelecer o tunnel

```bash
loading secrets from "/etc/ipsec.d/vpn1.secret"
"vpn1" #1: initiating Main Mode
```

E um dos logs mais legal de se ver é o que estabeleceu a SA, ou seja o tunnel está OK

```bash
"vpn1" #4: STATE_QUICK_I2: sent QI2, IPsec SA established tunnel mode {ESP=>0xb71ffca5 
```

Outro comando bem útil é o comando para verificar o status do ipsec

```bash
/usr/sbin/ipsec auto --status
```

Este comando irá retornar uma saída parecida com essa.

```bash
000 using kernel interface: netkey
000 interface lo/lo ::1
000 interface lo/lo 127.0.0.1
000 interface lo/lo 127.0.0.1
000 interface eth0/eth0 10.0.0.1
000 interface eth0/eth0 10.0.0.1
000 interface eth1/eth1 200.165.10.50
000 interface eth1/eth1 200.165.10.50
000 %myid = (none)
000 debug none
000
000 virtual_private (%priv):
000 - allowed 1 subnet: 10.0.0.0/8
000 - disallowed 0 subnets:
000 WARNING: Disallowed subnets in virtual_private= is empty. If you have
000 private address space in internal use, it should be excluded!
000
000 algorithm ESP encrypt: id=2, name=ESP_DES, ivlen=8, keysizemin=64, keysizemax=64
000 algorithm ESP encrypt: id=3, name=ESP_3DES, ivlen=8, keysizemin=192, keysizemax=192
000 algorithm ESP encrypt: id=6, name=ESP_CAST, ivlen=8, keysizemin=40, keysizemax=128
000 algorithm ESP encrypt: id=7, name=ESP_BLOWFISH, ivlen=8, keysizemin=40, keysizemax=448
000 algorithm ESP encrypt: id=11, name=ESP_NULL, ivlen=0, keysizemin=0, keysizemax=0
000 algorithm ESP encrypt: id=12, name=ESP_AES, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=13, name=ESP_AES_CTR, ivlen=8, keysizemin=160, keysizemax=288
000 algorithm ESP encrypt: id=14, name=ESP_AES_CCM_A, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=15, name=ESP_AES_CCM_B, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=16, name=ESP_AES_CCM_C, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=18, name=ESP_AES_GCM_A, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=19, name=ESP_AES_GCM_B, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=20, name=ESP_AES_GCM_C, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=22, name=ESP_CAMELLIA, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=252, name=ESP_SERPENT, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: id=253, name=ESP_TWOFISH, ivlen=8, keysizemin=128, keysizemax=256
000 algorithm ESP auth attr: id=1, name=AUTH_ALGORITHM_HMAC_MD5, keysizemin=128, keysizemax=128
000 algorithm ESP auth attr: id=2, name=AUTH_ALGORITHM_HMAC_SHA1, keysizemin=160, keysizemax=160
000 algorithm ESP auth attr: id=5, name=AUTH_ALGORITHM_HMAC_SHA2_256, keysizemin=256, keysizemax=256
000 algorithm ESP auth attr: id=6, name=AUTH_ALGORITHM_HMAC_SHA2_384, keysizemin=384, keysizemax=384
000 algorithm ESP auth attr: id=7, name=AUTH_ALGORITHM_HMAC_SHA2_512, keysizemin=512, keysizemax=512
000 algorithm ESP auth attr: id=8, name=AUTH_ALGORITHM_HMAC_RIPEMD, keysizemin=160, keysizemax=160
000 algorithm ESP auth attr: id=9, name=AUTH_ALGORITHM_AES_CBC, keysizemin=128, keysizemax=128
000 algorithm ESP auth attr: id=251, name=AUTH_ALGORITHM_NULL_KAME, keysizemin=0, keysizemax=0
000
000 algorithm IKE encrypt: id=0, name=(null), blocksize=16, keydeflen=131
000 algorithm IKE encrypt: id=5, name=OAKLEY_3DES_CBC, blocksize=8, keydeflen=192
000 algorithm IKE encrypt: id=7, name=OAKLEY_AES_CBC, blocksize=16, keydeflen=128
000 algorithm IKE hash: id=1, name=OAKLEY_MD5, hashsize=16
000 algorithm IKE hash: id=2, name=OAKLEY_SHA1, hashsize=20
000 algorithm IKE hash: id=4, name=OAKLEY_SHA2_256, hashsize=32
000 algorithm IKE hash: id=6, name=OAKLEY_SHA2_512, hashsize=64
000 algorithm IKE dh group: id=2, name=OAKLEY_GROUP_MODP1024, bits=1024
000 algorithm IKE dh group: id=5, name=OAKLEY_GROUP_MODP1536, bits=1536
000 algorithm IKE dh group: id=14, name=OAKLEY_GROUP_MODP2048, bits=2048
000 algorithm IKE dh group: id=15, name=OAKLEY_GROUP_MODP3072, bits=3072
000 algorithm IKE dh group: id=16, name=OAKLEY_GROUP_MODP4096, bits=4096
000 algorithm IKE dh group: id=17, name=OAKLEY_GROUP_MODP6144, bits=6144
000 algorithm IKE dh group: id=18, name=OAKLEY_GROUP_MODP8192, bits=8192
000 algorithm IKE dh group: id=22, name=OAKLEY_GROUP_DH22, bits=1024
000 algorithm IKE dh group: id=23, name=OAKLEY_GROUP_DH23, bits=2048
000 algorithm IKE dh group: id=24, name=OAKLEY_GROUP_DH24, bits=2048
000
000 stats db_ops: {curr_cnt, total_cnt, maxsz} :context={0,2,64} trans={0,2,3072} attrs={0,2,2048}
000
000 "vpn1": 10.0.0.0/24===200.165.10.50---200.165.10.1...200.165.10.1---201.80.24.7===10.0.1.0/24; erouted; eroute owner: #4
000 "vpn1": myip=unset; hisip=unset;
000 "vpn1": ike_life: 14400s; ipsec_life: 1200s; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 1
000 "vpn1": policy: PSK+ENCRYPT+TUNNEL+UP+IKEv2ALLOW+SAREFTRACK; prio: 24,24; interface: eth1;
000 "vpn1": newest ISAKMP SA: #1; newest IPsec SA: #4;
000 "vpn1": IKE algorithm newest: AES_CBC_128-SHA1-MODP2048
000 "vpn1": ESP algorithms wanted: 3DES(3)_000-MD5(1)_096; flags=-strict
000 "vpn1": ESP algorithms loaded: 3DES(3)_192-MD5(1)_096
000 "vpn1": ESP algorithm newest: 3DES_000-HMAC_MD5; pfsgroup=<N/A>
000
000 #3: "vpn1":4500 STATE_QUICK_R2 (IPsec SA established); EVENT_SA_REPLACE in 727s; isakmp#2; idle; import:not set
000 #3: "vpn1" esp.a0dfaa1a@201.80.24.7 esp.bf6f0287@200.165.10.50 tun.0@201.80.24.7 tun.0@200.165.10.50 ref=0 refhim=4294901761
000 #2: "vpn1":4500 STATE_MAIN_R3 (sent MR3, ISAKMP SA established); EVENT_SA_REPLACE in 13926s; lastdpd=-1s(seq in:0 out:0); idle; import:not set
000 #4: "vpn1":4500 STATE_QUICK_I2 (sent QI2, IPsec SA established); EVENT_SA_REPLACE in 453s; newest IPSEC; eroute owner; isakmp#1; idle; import:admin initiate
000 #4: "vpn1" esp.b71ffca5@201.80.24.7 esp.25fdf05f@200.165.10.50 tun.0@201.80.24.7 tun.0@200.165.10.50 ref=0 refhim=4294901761
000 #1: "vpn1":4500 STATE_MAIN_I4 (ISAKMP SA established); EVENT_SA_REPLACE in 13163s; newest ISAKMP; lastdpd=-1s(seq in:0 out:0); idle; import:admin initiate
000
```

Neste retorno há diversas informações, mas as mais importantes estão no final, onde mostram as SAs estabelecidas, ou seja, os tunneis IPSEC estabelecidos.

Pronto, a primeira fase da configuração está ok e nosso tunnel VPN estabelecido. Agora iniciaremos o processo para configuração utilizando certificado digital.

## **Gerando certificados digitais**

Antes de realizarmos a configuração do OpenSwan para utilizar os certificados digitais é necessário ter ou gerar os certificados. Como o objetivo deste post é ser o mais completo possível, realizaremos todo o processo de geração da autoridade certificadora e assinatura/geração dos certificados.

Se você não entende muito bem como funciona esse negócio de autoridade certificadora, cadeia de certificação segue alguns posts para você dar uma olhada antes de continuar:

- [Certificação digital](http://www.helviojunior.com.br/it/security/certificacao-digital/)
- [Instalando CA Root com OpenSSL](http://www.helviojunior.com.br/it/security/instalando-autoridade-certificadora-raiz-ca-root-com-openssl/)
- [Instalando CA Root com Windows](http://www.helviojunior.com.br/it/security/instalando-autoridade-certificadora-raiz-ca-root-com-windows/)
- [Verificando de um certificado é válido para atuar como CA](http://www.helviojunior.com.br/it/security/verificando-se-um-certificado-e-valido-para-atuar-como-uma-ca/)

Agora sim podemos continuar com a geração dos certificados. Neste post veremos 2 formas de gerar estes certificados, a primeira e a mais simples utilizando um aplicativo windows que criei para gerar os certificados e a segunda e mais complexa utilizando os comandos OpenSSL (que funcionam em windows e linux)

### Gerando certificados com o aplicativo BuildCert

Conforme ja comentado este aplicativo foi desenvolvido por mim especificamente para geração de certificados digitais para utilização em sistemas de VPN IPSEC, muitos dos aplicativos que realizam VPN IPSEC pedem configurações específicas nos certificados que são bem chatas de fazer através do openssl via linha de comando. Este aplicativo basicamente utiliza as próprias bibliotecas do OpenSSL para gerar os certificados.

Este aplicativo cria desde a CA até os certificados individuais de cada servidor de VPN. Todos compatíveis com qualquer sistema de autoridade de certificação. Outra funcionalidade interessante deste aplicativo é que pode ser utilizado com a sua autoridade de certificadora atual (caso ja tenha uma instalada).

**Utilizando a CA atual para assinar o certificado**

Para realizar este processo utilizando a sua CA atual será necessário ter o arquivo **.pfx** ou **.p12** da sua CA. Caso sua CA seja windows e você não saiba como realizar este procedimento no post [**Instalando CA Root com Windows**](http://www.helviojunior.com.br/it/security/instalando-autoridade-certificadora-raiz-ca-root-com-windows/) eu ensino como realiza-lo.

**Gerando certificado**

Realize o download do aplicativo BuildCert ([clicando aqui]({{ site.baseurl }}/assets/2014/10/BuildCert.zip)) e descompacte em qualquer lugar em seu PC. O Aplicativo terá a seguinte estrutura de arquivos, por mais que pareça que há duplicados todos são necessários.

[![BuildCertTree]({{ site.baseurl }}/assets/2014/10/BuildCertTree.png)]({{ site.baseurl }}/assets/2014/10/BuildCertTree.png)

Modo de utilização

```bash
BuildCert.exe [common_name_ca] [common_name_cert] [password_ca] [password_cert]
```

Ao ser iniciado o aplicativo irá buscar dentro do diretório certs o arquivo com o common mane da CA + a extensão pfx ex.: ca.meudominio.pfx, caso o arquivo exista o aplicativo irá abri-lo com a senha definida e utiliza-lo para assinar os certificados gerados, caso contrário o aplicativo irá criar este pfx e utiliza-lo para assinar os certificados gerados.

Vamos para a pratica, execute os comandos abaixo para gerar uma CA com nome **cavpn.tutorial** e os certificados **matriz.tutorial** e **filial.tutorial.** Ambos com a senha 123456

```bash
BuildCert.exe cavpn.tutorial matriz.tutorial 123456 123456
BuildCert.exe cavpn.tutorial filial.tutorial 123456 123456
```

Após a execução dos comandos 3 arquivos por certificado serão criados:

1. **.cer:** arquivo do certificado digital X509
2. **.key:** chave privada do certificado
3. **.pfx:** arquivo PKCS#12 contendo o certificado X509 + a chave privada

[![certs]({{ site.baseurl }}/assets/2014/10/certs.png)]({{ site.baseurl }}/assets/2014/10/certs.png)

Segue os prints dos certificados

[caption id="attachment_1112" align="alignnone" width="251"][![ca1]({{ site.baseurl }}/assets/2014/10/ca1.png)]({{ site.baseurl }}/assets/2014/10/ca1.png) Certificado da CA (Autoassinado)[/caption]

[caption id="attachment_1113" align="alignnone" width="251"][![ca2]({{ site.baseurl }}/assets/2014/10/ca2.png)]({{ site.baseurl }}/assets/2014/10/ca2.png) Certificado da matriz assinado pela CA[/caption]

[caption id="attachment_1114" align="alignnone" width="251"][![ca3]({{ site.baseurl }}/assets/2014/10/ca3.png)]({{ site.baseurl }}/assets/2014/10/ca3.png) Certificado da filial assinado pela CA[/caption]

Pronto, os certificados foram gerados e estão prontos para serem utilizados no OpenSwan

### Gerando certificados com o OpenSSL

Outro modo de gerar os certificados é utilizando diretamente o OpenSSL.

Se você ja gerou os certificados através dos passos anteriores (aplicativo BuildCert) pode pular estes passos e ir direto para configuração dos tunneis.

**Gerando certificado**

Antes de tudo vamos preparar o ambiente para o OpenSSL, realize uma cópia do arquivo de configuração padrão do OpenSSL para o seu ambiente

```bash
cp cp /etc/ssl/openssl.cnf /etc/ipsec.d/
```

Edite o arquivo de configuração alterando as seguintes linhas

```bash
[ CA_default ]

dir = /etc/ipsec.d
certificate = $dir/cacerts/cavpn.tutorial.cer

private_key = $dir/private/cavpn.tutorial.key
```

E por fim vamos criar arquivos e diretórios necessários para o correto funcionamento do OpenSSL

```bash
mkdir newcerts
touch index.txt
echo "00" > serial
```

Agora vamos criar a nossa CA através do comando abaixo

```bash
cd /etc/ipsec.d
openssl req -x509 -days 3650 -config /etc/ipsec.d/openssl.cnf -newkey rsa:2048 -keyout private/cavpn.tutorial.key -out cacerts/cavpn.tutorial.cer
```

Na execução deste comando diversas informações serão solicitadas, porém 2 delas são importantes, 1 - Senha da CA, essa senha será solicitada para assinar os certificados da matriz e da filial; 2 - CommonName, ou seja o nome da CA. Preencha estes dados conforme desejado ou seguindo o exemplo abaixo

[![cert1]({{ site.baseurl }}/assets/2014/10/cert1.png)]({{ site.baseurl }}/assets/2014/10/cert1.png)

Gere a requisição e assine o certificado da matriz

```bash
openssl req -config /etc/ipsec.d/openssl.cnf -newkey rsa:1024 -keyout private/matriz.tutorial.key -out certs/matriz.tutorial.req
openssl ca -in certs/matriz.tutorial.req -config /etc/ipsec.d/openssl.cnf -days 730 -out certs/matriz.tutorial.cer -notext
openssl rsa -in private/matriz.tutorial.key -out private/matriz.tutorial.key
```

Diversas informações serão solicitadas porém a mais importante é o CommonName que precisa ser o **matriz.tutorial** para que os próximos scripts funcionem corretamente

[![cert-matriz]({{ site.baseurl }}/assets/2014/10/cert-matriz.png)]({{ site.baseurl }}/assets/2014/10/cert-matriz.png)

Gere a requisição e assine o certificado da filial

```bash
openssl req -config /etc/ipsec.d/openssl.cnf -newkey rsa:1024 -keyout private/filial.tutorial.key -out certs/filial.tutorial.req
openssl ca -in certs/filial.tutorial.req -config /etc/ipsec.d/openssl.cnf -days 730 -out certs/filial.tutorial.cer -notext
openssl rsa -in private/filial.tutorial.key -out private/filial.tutorial.key
```

Diversas informações serão solicitadas porém a mais importante é o CommonName que precisa ser o **filial.tutorial** para que os próximos scripts funcionem corretamente

[![cert-filial]({{ site.baseurl }}/assets/2014/10/cert-filial.png)]({{ site.baseurl }}/assets/2014/10/cert-filial.png)

Pronto, os certificados estão gerados e pronto para serem utilizados.

## Configurando os tunneis ipsec para utilizar os certificados digitais

Agora que temos todos os certificados a mão podemos iniciar a configuração do OpenSwan para estabelecer a VPN utilizando os certificados digitais, estes passos são individuais para cada servidor.

### VPN Server Matriz

Copie os arquivos necessários para os seus respectivos locais de utilização conforme indicado na tabela abaixo:

- /etc/ipsec.d/cacerts/cavpn.tutorial.cer
- /etc/ipsec.d/certs/filial.tutorial.cer
- /etc/ipsec.d/certs/matriz.tutorial.cer
- /etc/ipsec.d/private/matriz.tutorial.key

Edite o arquivo **/etc/ipsec.d/vpn1.conf** para que o mesmo fique com o seguinte conteúdo

```bash
conn vpn1 # Nome da Conexão VPN
	type= tunnel
	authby= rsasig #Tipo de autenticação

	# Left security, (dados da Matriz)
	left= 200.165.10.50 # IP real/físico do servidor na matriz
	leftid=@matriz.tutorial # CommonName do certificado
	leftrsasigkey=%cert
	leftcert=matriz.tutorial.cer # Nome do arquivo do certificado
	leftsubnet= 10.0.0.0/24 # Rede interna na Matriz para qual será estabelecido a VPN
	leftnexthop= 200.165.10.1 # IP real do Gateway do servidor de VPN da Matriz

	# Right security, (dados da Filial)
	right= %any # Está tag indica que a conexão pode vir de qualquer IP
	rightid= @filial.tutorial # CommonName do certificado
	rightrsasigkey=%cert
	rightcert=filial.tutorial.cer # Nome do arquivo do certificado
	rightca=%same
	rightsubnet= 10.0.1.0/24 # Rede interna da filial para qual será estabelecido a VPN
	rightnexthop= 200.165.10.1 # IP real do Gateway do servidor de VPN da Matriz

	# Tipo de criptografia usada
	keyexchange=ike

	# IPSEC Fase 1
	# Não é obrigatório o preenchimento, caso preenchido será restrito a estes protocolos preenchidos
	# Formato de preenchimento 'cipher-hash;modpgroup, cipher-hash;modpgroup, ...'
	#   -> Não é obrigatório o preenchimento do modpgroup
	# cipher-hash disponíveis: 3des-sha1, 3des-md5, aes-sha1, aes-md5, aes128-sha1 e aes128-md5
	# modpgroup disponíveis: modp1024, modp1536 e modp2048
	ike= 3des-md5,3des-sha1,aes-sha1,aes-md5,aes128-sha1,aes128-md5
	ikelifetime=28800s

	# IPSEC Fase 2
	# cipher-hash disponíveis: 3des, 3des-md5-96, 3des-sha1-96
	phase2=esp
	phase2alg=3des-md5-96 # Antigo parametro 'esp' que está obsoleto
	keylife=28800s

	# Outras configurações
	pfs= no
	auto= start
```

Além das alterações dos certificados digitais há uma alteração no parâmetro **right** que antes detinha o IP externo do servidor de VPN da filial e agora detém a tag **%any**, que possibilita que o IP externo do servidor de VPN da Filial possa trocar de IP sem a necessidade de alterar a configuração.

Edite o arquivo **/etc/ipsec.d/vpn1.secret**, remova a linha atual e adicione a seguinte linha

```bash
: RSA matriz.tutorial.key "123456"
```

Reinicie o serviço do ipsec e verifique no arquivo de log **/var/log/auth.log** se as linhas abaixo foram exibidas, elas indicam que a chave foi lida com sucesso.

```bash
loading secrets from "/etc/ipsec.d/vpn1.secret"
loaded private key file '/etc/ipsec.d/private/matriz.tutorial.key' (1675 bytes)
loaded private key for keyid: PPK_RSA:AwEAAfL4J
"vpn1" #1: initiating Main Mode
```

### VPN Server Filial

Copie os arquivos necessários para os seus respectivos locais de utilização conforme indicado na tabela abaixo:

- /etc/ipsec.d/cacerts/cavpn.tutorial.cer
- /etc/ipsec.d/certs/filial.tutorial.cer
- /etc/ipsec.d/certs/matriz.tutorial.cer
- /etc/ipsec.d/private/filial.tutorial.key

Edite o arquivo **/etc/ipsec.d/vpn1.conf** para que o mesmo fique com o seguinte conteúdo

```bash
conn vpn1 # Nome da Conexão VPN
	type= tunnel
	authby= rsasig #Tipo de autenticação

	# Left security, (dados da Filial)
	left= 192.168.0.10 # IP real/físico do servidor na filial
	leftid=@filial.tutorial # CommonName do certificado
	leftrsasigkey=%cert
	leftcert=filial.tutorial.cer # Nome do arquivo do certificado
	leftsubnet= 10.0.1.0/24 # Rede interna na filial para qual será estabelecido a VPN
	leftnexthop= 192.168.0.1 # IP real do Gateway do servidor de VPN da filial

	# Right security, (dados da Matriz)
	right= 200.165.10.50 # IP externo do servidor na matriz
	rightid= @matriz.tutorial # CommonName do certificado
	rightrsasigkey=%cert
	rightcert=matriz.tutorial.cer # Nome do arquivo do certificado
	rightca=%same
	rightsubnet= 10.0.0.0/24 # Rede interna da matriz para qual será estabelecido a VPN
	rightnexthop= 192.168.0.1 # IP real do Gateway do servidor de VPN da filial

	# Tipo de criptografia usada
	keyexchange=ike

	# IPSEC Fase 1
	# Não é obrigatório o preenchimento, caso preenchido será restrito a estes protocolos preenchidos
	# Formato de preenchimento 'cipher-hash;modpgroup, cipher-hash;modpgroup, ...'
	#   -> Não é obrigatório o preenchimento do modpgroup
	# cipher-hash disponíveis: 3des-sha1, 3des-md5, aes-sha1, aes-md5, aes128-sha1 e aes128-md5
	# modpgroup disponíveis: modp1024, modp1536 e modp2048
	ike= 3des-md5,3des-sha1,aes-sha1,aes-md5,aes128-sha1,aes128-md5
	ikelifetime=28800s

	# IPSEC Fase 2
	# cipher-hash disponíveis: 3des, 3des-md5-96, 3des-sha1-96
	phase2=esp
	phase2alg=3des-md5-96 # Antigo parametro 'esp' que está obsoleto
	keylife=28800s

	# Outras configurações
	pfs= no
	auto= start
```

Edite o arquivo **/etc/ipsec.d/vpn1.secret**, remova a linha atual e adicione a seguinte linha

```bash
: RSA filial.tutorial.key "123456"
```

Reinicie o serviço do ipsec e verifique no arquivo de log **/var/log/auth.log** se as linhas abaixo foram exibidas, elas indicam que a chave foi lida com sucesso.

```bash
loading secrets from "/etc/ipsec.d/vpn1.secret"
loaded private key file '/etc/ipsec.d/private/filial.tutorial.key' (1679 bytes)
loaded private key for keyid: PPK_RSA:AwEAAdWyO
```

## Troubleshooting

Caso seja necessário ter um numero maior de informações e log basta adicionar as linhas de log no arquivo **/etc/ipsec.conf** conforme abaixo

```bash
version 2.0
config setup
        ...
        plutodebug=all
        plutostderrlog=/var/log/openswan.log
```

## Considerações finais

Neste post vimos como realizar todo o procedimento utilizando como servidor de VPN dois equipamentos com o OpensSwan, porém o procedimento é exatamente o mesmo para ambientes onde um dos equipamentos não é OpenSwan, como por exemplo, Cisco, Microsoft TMG, Aker, pfSense, Dlink entre outros.

Como continuidade irei demonstrar como substituir o equipamento da matriz por outros sistemas. Assim que tiver um tempo elaborarei estes outros tutoriais e posto aqui no site.

Caso você quera compartilhar a sua experiência substituindo uma das pontas por outro equipamento, me envie o passo a passo com prints, comandos e arquivos de configuração que posto no site com os seus créditos.
