---
layout: post
title: Instalando Elasticsearch EDR
date: 2024-06-01 05:00:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/security/edr/instalando-elasticsearch-edr/"
---

## Instalando Elasticsearch EDR

Durante a minha pesquisa de Bypass de EDR e criação da técnica [HookChain](https://github.com/helviojunior/hookchain/) eu me deparei com uma dificuldade para achar um tutorial passo-a-passo que realmente incluisse todos os passos para a instalação e configuração do Elastic EDR, sendo assim decidi escreve-lo.

Segue um passo a passo para instalação do Elasticsearch EDR no Ubuntu.

### Preparando Ambiente

Primeiro passo é realizar a instalação dos pacotes necessários:


```shell
apt update
apt install python3 python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools python3-venv unzip jq curl apt-transport-https
```

### Instalando o ELK

Adicione o repositório do ELK e atualize a listagem de pacotes:

```shell
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
apt update
```

E por fim, instale o ELK:

```shell
apt install elasticsearch kibana
```

## Gerando certificados digitais

Para este ambiente será necessário a criação e utilização de certificados digitais para as comunicações TLS.

Crie um arquivo `/usr/share/elasticsearch/instances.yml` com o seguinte conteúdo


```yml
instances:
    - name: "elasticsearch"
      ip:
        - "172.31.255.30"
    - name: "kibana"
      ip:
        - "172.31.255.30"
    - name: "zeek"
      ip:
        - "172.31.255.30"
```
{: file='/usr/share/elasticsearch/instances.yml'}

> Altere o endereço IP `172.31.255.30` do arquivo de configuração acima para o endereço IP e/ou nome DNS utilizado em seu ambiente. O IP acima é o endereço do servidor ELK
{: .prompt-warning }

> O `ELK` pode ser configurado para utilizar nome DNS ou IP, para este artigo e em meu ambiente de testes, estarei utilizando IP. Desta forma lembre-se de alterar no arquivo de configuração acima para o endereço IP e/ou nome DNS utilizado em seu ambiente. O IP acima é o endereço do servidor ELK
{: .prompt-tip }


```shell
cd /usr/share/elasticsearch/
/usr/share/elasticsearch/bin/elasticsearch-certutil ca --silent  --keysize 2048 --pass "" --pem --out ca.zip
unzip ca.zip -d .
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent  --in instances.yml --keysize 2048 --pem --out certs.zip --ca-cert ./ca/ca.crt --ca-key ./ca/ca.key --ca-pass ""
unzip certs.zip -d .
```

Adicione o certificado da CA Root gerada como confiávem no próprio Linux. Este procesimento é necessário pois futiramente utilizaremos este mesmo servidor como o agente de um dos componentes do EDR (Fleet Server).

```bash
cp /usr/share/elasticsearch/ca/ca.crt /usr/local/share/ca-certificates/
update-ca-certificates
```


Agora crie e copie os certificados para as estruturas de diretórios do Elasticsearch e Kibana

```shell
mkdir /etc/elasticsearch/certs/ca -p
mkdir /etc/kibana/certs/ca -p

cd /usr/share/elasticsearch/

cp ca/ca.crt /etc/elasticsearch/certs/ca
cp elasticsearch/elasticsearch.crt /etc/elasticsearch/certs
cp elasticsearch/elasticsearch.key /etc/elasticsearch/certs
chown -R elasticsearch: /etc/elasticsearch/certs
chmod -R 770 /etc/elasticsearch/certs

cp ca/ca.crt /etc/kibana/certs/ca
cp kibana/kibana.crt /etc/kibana/certs
cp kibana/kibana.key /etc/kibana/certs
chown -R kibana: /etc/kibana/certs
chmod -R 770 /etc/kibana/certs
```


### Configurando o Elasticsearch

Edite o arquivo de configuração `/etc/elasticsearch/elasticsearch.yml`

```shell
http.host: 0.0.0.0
network.host: "172.31.255.30"
http.port: 9200
node.name: "node-1"
cluster.initial_master_nodes: ["node-1"]
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

xpack.security.enrollment.enabled: true

xpack.security.enabled: true

# Transport layer
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]

# HTTP layer
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.verification_mode: certificate
xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]
```
{: file='/etc/elasticsearch/elasticsearch.yml'}


Habilite e inicie o serviço


```shell
systemctl enable elasticsearch
systemctl start elasticsearch
systemctl status elasticsearch
```

Se tudo ocorreu conforme o esperado, teremos um resultado conforme a imagem abaixo

[![]({{site.baseurl}}/assets/2024/06/12d0a79abb77dd4c3d28a55eb8b4e35f.png)]({{site.baseurl}}/assets/2024/06/12d0a79abb77dd4c3d28a55eb8b4e35f.png)

Podemos verificar a conexão através do comando abaixo

```shell
curl -s -k -X GET "https://localhost:9200" | jq
```

[![]({{site.baseurl}}/assets/2024/06/7aeb4442e68a0242b85123edffdfb238.png)]({{site.baseurl}}/assets/2024/06/7aeb4442e68a0242b85123edffdfb238.png)

> Com o comando acima recebemos um erro de autenticação `missing authentication credentials for REST request`, porém não se preocupe isso é normal, pois ja configuramos o nosso Elasticsearch para exigir autenticação em sua interações, inclusive na API REST.
{: .prompt-tip }

Agora vamos resetar as credenciais do sistema

```
for u in "elastic" "apm_system" "kibana_system" "kibana" "logstash_system" "remote_monitoring_user"; do echo; /usr/share/elasticsearch/bin/elasticsearch-reset-password -b -u $u; done
```

> Armazene essas credenciais em local seguro. Utilizaremos o usuário `elastic` para login no kibana via HTTPS
{: .prompt-warning }


Como estamos executando nossos comandos como usuário root, vamos nos certificar que os usuários e grupos estão corretos. 

```shell
chown -R elasticsearch:elasticsearch /etc/elasticsearch*
chown elasticsearch:elasticsearch /etc/elasticsearch/service_tokens
```

Reinicie o serviço do elasticsearch

```shell
systemctl restart elasticsearch
```

### Configurando o Kibana

Gere as chaves de criptografia

```shell
/usr/share/kibana/bin/kibana-encryption-keys generate --force
```

Edite o arquivo de configuração `/etc/kibana/kibana.yml` conforme abaixo


```yml
# =================== System: Kibana Server ===================
# Kibana is served by a back end server. This setting specifies the port to use.
server.port: 443
server.host: "0.0.0.0"
server.publicBaseUrl: "https://172.31.255.30"

# =================== System: Logging ===================
# Set the value of this setting to off to suppress all logging output, or to debug to log everything. Defaults to 'info'
#logging.root.level: debug

# Enables you to specify a file where Kibana stores log output.
logging:
  appenders:
    file:
      type: file
      fileName: /var/log/kibana/kibana.log
      layout:
        type: json
  root:
    appenders:
      - default
      - file

# Specifies the path where Kibana creates the process ID file.
pid.file: /run/kibana/kibana.pid

# The URLs of the Elasticsearch instances to use for all your queries.
elasticsearch.hosts: ["https://172.31.255.30:9200"]
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca/ca.crt"]
elasticsearch.ssl.certificate: "/etc/kibana/certs/kibana.crt"
elasticsearch.ssl.key: "/etc/kibana/certs/kibana.key"

# These settings enable SSL for outgoing requests from the Kibana server to the browser.
server.ssl.enabled: true
server.ssl.certificate: "/etc/kibana/certs/kibana.crt"
server.ssl.key: "/etc/kibana/certs/kibana.key"

# Elastic Credentials
elasticsearch.username: "kibana_system"  # Not use elastic or kibana user
elasticsearch.password: "Your_Elastic_Pass_Here"

xpack.security.encryptionKey: "myKey"
xpack.encryptedSavedObjects.encryptionKey: "myEncKey"
xpack.reporting.encryptionKey: "my2EncKey"
```
{: file='/etc/kibana/kibana.yml'}

> Lembre-se de alterar os valores das chaves de criptografia `xpack.security.encryptionKey`, `xpack.encryptedSavedObjects.encryptionKey` e `xpack.reporting.encryptionKey`, a senha do usuário `kibana_system` bem como o endereço IP presente no parâmetro `server.publicBaseUrl`.
{: .prompt-warning }

> Por rasões internas da ELK não é possível utilizar os usuários `kibana` e `elastic` como parâmetro `elasticsearch.username`, sendo assim se certifique de utilizar o usuário `kibana_system`
{: .prompt-tip }

Como configuramos o Kibana para realizar o bind diretamente na port 443 (HTTPS) será necessário permitir que os binários do kibana tenham este acesso. Realiza isso com os comandos abaixo:

```bash
setcap cap_net_bind_service=+epi /usr/share/kibana/bin/kibana
setcap cap_net_bind_service=+epi /usr/share/kibana/bin/kibana-plugin
setcap cap_net_bind_service=+epi /usr/share/kibana/bin/kibana-keystore
setcap cap_net_bind_service=+epi /usr/share/kibana/node/bin/node
```

Por fim habilite e inicie o serviço do Kibana

```bash
systemctl enable kibana
systemctl start kibana
systemctl status kibana
```

#### Acesso ao Kibana

Caso tudo tenha ocorrido corretamente, ao acessar a URL do kibana (em nosso ambiente `https://172.31.255.30`) veremos a tela de login, conforme a imagem abaixo.

[![]({{site.baseurl}}/assets/2024/06/ff9c3f5a4c62685edfb3c9dacaaf7c0b.png)]({{site.baseurl}}/assets/2024/06/ff9c3f5a4c62685edfb3c9dacaaf7c0b.png)

Para o acesso utilize o usuário `elastic` e a senha gerada anteriormente.

Em nosso primeiro login veremos a imagem abaixo

[![]({{site.baseurl}}/assets/2024/06/405b41a53990670ecbaf7a8e94fdbb95.png)]({{site.baseurl}}/assets/2024/06/405b41a53990670ecbaf7a8e94fdbb95.png)

Neste momento podemos pressionar no botão `Explore on my own` para seguir para a console principal do Kibana.

## ELK Fleet

### Fleet, mas o que é isso?

Em meu primeiro contato com o ELK EDR, confesso que me bati um monte para conseguir entender (pelo menos acho que entendi) de forma básica o funcionamento.

Primeiramente necessitamos criar um servidor chamado `Fleet Server` que será o componente responsável pela centralização e gerenciamento de agentes que coletam e enviam dados para o Elasticsearch, posteriormente iremos instalar os `Agentes Fleet` que serão efetivamente os nossos EDRs.

Para este processo utilizaremos uma integração do ELK chamada `Elastic Defend`.

### Instalação e configuração do Fleet Server

Acesse o painel de configuração do Fleet

[![]({{site.baseurl}}/assets/2024/06/73bbc7a151247d301eb0461820def5b0.png)]({{site.baseurl}}/assets/2024/06/73bbc7a151247d301eb0461820def5b0.png)

[![]({{site.baseurl}}/assets/2024/06/073800641ae6370e230984f1293ecc5c.png)]({{site.baseurl}}/assets/2024/06/073800641ae6370e230984f1293ecc5c.png)

Clique em `Add Fleet Server`, e configure conforme a imagem abaixo

[![]({{site.baseurl}}/assets/2024/06/c525ede21fa9015c2bf9e5ad7dd8ef9c.png)]({{site.baseurl}}/assets/2024/06/c525ede21fa9015c2bf9e5ad7dd8ef9c.png)

E clique em `Generate Fleet Server policy` e aguarde a geração, este processo pode demorar alguns segundos. Ao finalizar teremos a seguinte informação.

[![]({{site.baseurl}}/assets/2024/06/0309b2ca506632887b9f81b53eda9db6.png)]({{site.baseurl}}/assets/2024/06/0309b2ca506632887b9f81b53eda9db6.png)

Copie o comando fornecido, mas não o execute ainda pois precisaremos ajustar alguns parâmetros.

Realize o download e extração do pacote fornecido

```bash
cd /tmp
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.14.1-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.14.1-linux-x86_64.tar.gz
cd elastic-agent-8.14.1-linux-x86_64
```

```bash
sudo ./elastic-agent install --url=https://172.31.255.30:8220 \
  --fleet-server-es=https://172.31.255.30:9200 \
  --fleet-server-service-token=AAEAAWVsYXN0aWMvZmxlZXQtc2VydmVyL3Rva2VuLTE3MTk4MzUyODkzODI6WDhFYWx0RGZSNHVlYmhhZkxzeUFsQQ \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-port=8220 \
  --certificate-authorities=/etc/elasticsearch/certs/ca/ca.crt \
  --fleet-server-es-ca=/etc/elasticsearch/certs/ca/ca.crt \
  --fleet-server-cert=/etc/elasticsearch/certs/elasticsearch.crt \
  --fleet-server-cert-key=/etc/elasticsearch/certs/elasticsearch.key
```

> Note que precisamos inserir os parâmetros `--url`, `--certificate-authorities`, `--fleet-server-es-ca`, `--fleet-server-cert` e `--fleet-server-cert-key`. Bem como precisamos alterar o parâmetro `--fleet-server-es` para ao invés de usar `http` e `localhost` utilizar `https` com o endereço IP do nosso servidor ELK.
{: .prompt-tip }

Caso nenhum erro ocorra, receberemos  um resultado conforma abaixo:

[![]({{site.baseurl}}/assets/2024/06/eefb80ba7548ee8c205f8b0eed3d0664.png)]({{site.baseurl}}/assets/2024/06/eefb80ba7548ee8c205f8b0eed3d0664.png)

E na interface web conforme abaixo:

[![]({{site.baseurl}}/assets/2024/06/f6c615e7edfdb9daa504224a825a5732.png)]({{site.baseurl}}/assets/2024/06/f6c615e7edfdb9daa504224a825a5732.png)

Caso encontre algum erro neste processo basta desinstalar o agente com o comando `/usr/bin/elastic-agent uninstall`, ajustar o problema e realizar a instalação novamente.

> Na interface gráfica basta fechar a janela de confiruração. `NÃO` sendo necessário clicar em `Continue enrolling Elastic Agent`.
{: .prompt-warning }

Após fechar o painel lateral de configuração a seguinte tela será exibida, indicando que a configuração ocorreu com sucesso.

[![]({{site.baseurl}}/assets/2024/06/68cd89661c2bee9aff4d092e9ba5ba51.png)]({{site.baseurl}}/assets/2024/06/68cd89661c2bee9aff4d092e9ba5ba51.png)

Edite as configurações do Fleet para que os hosts possam integrar corretamente através do IP/Nome do servidor. 

[![]({{site.baseurl}}/assets/2024/06/6febdbf2323a30ab868309b577215091.png)]({{site.baseurl}}/assets/2024/06/6febdbf2323a30ab868309b577215091.png)

### Integração EDR

Para o correto monitoramento e encaminhamento de logs e alertas vamos configurar a integração com o o Elastic Defend para o Fleet Server

[![]({{site.baseurl}}/assets/2024/06/f3bbf063ae7b929d265569c4a4207e8f.png)]({{site.baseurl}}/assets/2024/06/f3bbf063ae7b929d265569c4a4207e8f.png)

[![]({{site.baseurl}}/assets/2024/06/86108d5989dfea7c9a7ad3c6a6ed22f3.png)]({{site.baseurl}}/assets/2024/06/86108d5989dfea7c9a7ad3c6a6ed22f3.png)

[![]({{site.baseurl}}/assets/2024/06/2cad626baeab80c32dcb5187e5369e7e.png)]({{site.baseurl}}/assets/2024/06/2cad626baeab80c32dcb5187e5369e7e.png)

[![]({{site.baseurl}}/assets/2024/06/eb10d8a0475575c6fd7b40f8ec453e23.png)]({{site.baseurl}}/assets/2024/06/eb10d8a0475575c6fd7b40f8ec453e23.png)

[![]({{site.baseurl}}/assets/2024/06/2e24bf5ea88211c98b491321dcd254ab.png)]({{site.baseurl}}/assets/2024/06/2e24bf5ea88211c98b491321dcd254ab.png)


## Elastic Defend

### Agent policy

Primeiro passo necessário para a configuração de um agente do EDR, é a criação de uma política.

[![]({{site.baseurl}}/assets/2024/06/e7ada731ce7414326236bb8fd558672b.png)]({{site.baseurl}}/assets/2024/06/e7ada731ce7414326236bb8fd558672b.png)

Digite o nome desejado, em meu caso utilizei `EDR Policy` e clique em `Create agent policy`

[![]({{site.baseurl}}/assets/2024/06/8723ab754c15d224387a94c60b8dbdee.png)]({{site.baseurl}}/assets/2024/06/8723ab754c15d224387a94c60b8dbdee.png)

Clique na política criada

[![]({{site.baseurl}}/assets/2024/06/2d86612c2974070e67d816c4de15e8a6.png)]({{site.baseurl}}/assets/2024/06/2d86612c2974070e67d816c4de15e8a6.png)

E adicione uma integração com o `Elastic Defend`

[![]({{site.baseurl}}/assets/2024/06/3d3eabeebd2bb0b5ecc8799fed99b84c.png)]({{site.baseurl}}/assets/2024/06/3d3eabeebd2bb0b5ecc8799fed99b84c.png)

[![]({{site.baseurl}}/assets/2024/06/2cad626baeab80c32dcb5187e5369e7e.png)]({{site.baseurl}}/assets/2024/06/2cad626baeab80c32dcb5187e5369e7e.png)

[![]({{site.baseurl}}/assets/2024/06/eb10d8a0475575c6fd7b40f8ec453e23.png)]({{site.baseurl}}/assets/2024/06/eb10d8a0475575c6fd7b40f8ec453e23.png)


E configure a integração conforme desejado.

[![]({{site.baseurl}}/assets/2024/06/69550439856723bb1271f57df9409c68.png)]({{site.baseurl}}/assets/2024/06/69550439856723bb1271f57df9409c68.png)


> Conheça um pouco maais sobre os modos de proteção na documentação da Elastic em [https://www.elastic.co/guide/en/security/current/configure-endpoint-integration-policy.html](https://www.elastic.co/guide/en/security/current/configure-endpoint-integration-policy.html).
{: .prompt-tip }

Depois de adicionar a integração basta clicar em `Add Elastic Agent later` e retornaremos a página das políticas.

[![]({{site.baseurl}}/assets/2024/06/6f9bb95f92c3c09bf9d4214fca4856ff.png)]({{site.baseurl}}/assets/2024/06/6f9bb95f92c3c09bf9d4214fca4856ff.png)


### Ajustando a política do EDR

Agora que temos a nossa política criada podemos ajustar os seus devidos parâmetros.

Clique no nome da política.

[![]({{site.baseurl}}/assets/2024/06/56036e71455de34b03c21e7b819ed7cb.png)]({{site.baseurl}}/assets/2024/06/56036e71455de34b03c21e7b819ed7cb.png)

E seremos, então direcionado para as configurações do Elastic Defender

[![]({{site.baseurl}}/assets/2024/06/992191884c193b48ec7c975d39aa7370.png)]({{site.baseurl}}/assets/2024/06/992191884c193b48ec7c975d39aa7370.png)

Ajuste as configurações conforme desejado e por fim defina para que o Endpoint seja registrado como o provedor oficial de proteção da máquina windows.

[![]({{site.baseurl}}/assets/2024/06/27ddca12f7691bc1174267d00b084605.png)]({{site.baseurl}}/assets/2024/06/27ddca12f7691bc1174267d00b084605.png)


## Agent Windows

Neste momento podemos realizar a instalação do agente em nossos Endpoint Windows

### Certificado TLS

Antes de realizar a instalação do Agente no windows será necessário cadastrar a CA do Elastic como CA Root confiável.

Copie o arquivo `/usr/share/elasticsearch/ca/ca.crt` para o windows e instale-o como `CA Root Confiável` em `Local Machine`.

[![]({{site.baseurl}}/assets/2024/06/9c50fa1d48627feba299cc602cf9fb52.png)]({{site.baseurl}}/assets/2024/06/9c50fa1d48627feba299cc602cf9fb52.png)


[![]({{site.baseurl}}/assets/2024/06/48bb6155730de276c048be27997f31eb.png)]({{site.baseurl}}/assets/2024/06/48bb6155730de276c048be27997f31eb.png)

### Instalando agente

Ainda na console do Kibana clique em `Add Agent`

[![]({{site.baseurl}}/assets/2024/06/1f2f6b2b2327afc74746bab215f82f83.png)]({{site.baseurl}}/assets/2024/06/1f2f6b2b2327afc74746bab215f82f83.png)

Inicie um powershell com permissões administrativas e execute os comandos obtidos.

```
cd c:\windows\temp

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.14.1-windows-x86_64.zip -OutFile elastic-agent-8.14.1-windows-x86_64.zip
Expand-Archive .\elastic-agent-8.14.1-windows-x86_64.zip -DestinationPath .

cd elastic-agent-8.14.1-windows-x86_64

.\elastic-agent.exe install --url=https://172.31.255.30:8220 --enrollment-token=...
```

[![]({{site.baseurl}}/assets/2024/06/8e96143351568bee9f2ac6463c76ea4c.png)]({{site.baseurl}}/assets/2024/06/8e96143351568bee9f2ac6463c76ea4c.png)


> Observe que eu executer os comandos dentro do diretório `c:\windows\temp`.
{: .prompt-tip }

Neste momento na console web veremos que o agente foi instalado corretamente.

[![]({{site.baseurl}}/assets/2024/06/9f2e263d20b913c525c38ad1bef7ac2e.png)]({{site.baseurl}}/assets/2024/06/9f2e263d20b913c525c38ad1bef7ac2e.png)

[![]({{site.baseurl}}/assets/2024/06/c7cb2b1bb22daedcfd2cc76a7a318e4d.png)]({{site.baseurl}}/assets/2024/06/c7cb2b1bb22daedcfd2cc76a7a318e4d.png)

Para a visualização do(s) provedores de proteção da máquina basta executar o comando powershell `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct`

[![]({{site.baseurl}}/assets/2024/06/9cadf84c55ce34a98d1effcf3a93d7be.png)]({{site.baseurl}}/assets/2024/06/9cadf84c55ce34a98d1effcf3a93d7be.png)


## Testes de identificação

Vamos colocar o EDR a prova de fogo? Para isso realizei a copia e tentativa de execução do Mimikatz.

Quase que instantaneamente foi bloqueado e o arquivo removido.

[![]({{site.baseurl}}/assets/2024/06/8a8cc63778b425adf9e1d1c4d858ae8f.png)]({{site.baseurl}}/assets/2024/06/8a8cc63778b425adf9e1d1c4d858ae8f.png)


[![]({{site.baseurl}}/assets/2024/06/d2fe28eae1767c8b3218534540e1ca11.png)]({{site.baseurl}}/assets/2024/06/d2fe28eae1767c8b3218534540e1ca11.png)


## Conclusão

Este foi o processo de instalação e configuração inicial, mas certamente tem bem mais ajustes finos a serem realizados.

Querem saber um pouco mais como ele se comportou nos testes de Bypass? Nos acompanha nas redes sociais em nosso Github que tem novidades!

## Referencias:

- [How to install Elastic SIEM and Elastic EDR](https://newtonpaul.com/how-to-install-elastic-siem-and-elastic-edr/)
- [Elastic Defend - Entendendo as funcionalidades do EDR da Elastic](https://medium.com/@souzaw/elastic-defend-entendendo-as-funcionalidades-do-edr-da-elastic-663c4e8bb94c)





