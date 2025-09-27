---
layout: post
title: Instalando SonarQube
date: 2025-09-27 19:00:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Code Review
tags:
- Offensive Security
- Code Review
author: Helvio Junior (m4v3r1ck)
permalink: "/security/code_review/instalando_sonarqube/"
excerpt: "Passo a passo de instalação do SonarQube"
image:
  src: /assets/2025/09/b59d929bc8ebff8919f0e14751860e3c.png
  alt: SonarQube
---


## Instalando PostgreSql 

Importe a chave do repositório
```bash
sudo apt install curl ca-certificates
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc
```

Crie o arquivo de config do repo
```
sudo sh -c "echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release --codename --short)-pgdg main' > /etc/apt/sources.list.d/pgdg.list"
```

Atualize os repositórios e instale o PostereSQL

```bash
sudo apt update

sudo apt -y install postgresql-15
```

Habilite e inicie o banco de dados
```bash
systemctl enable postgresql
systemctl start postgresql
```

## Configure o PostgreSQL

Entre na cli do banco

```bash
sudo -u postgres psql
```

Crie o usuário `sonarqube` com a senha desejada

```bash
postgres=# CREATE ROLE sonarqube WITH LOGIN ENCRYPTED PASSWORD 'MySuperSecretPassword';
```

Crie a base de dados

```bash
postgres=# CREATE DATABASE sonarqube;
```

Permita o usuário com acesso total a essa base de dados

```bash
postgres=# GRANT ALL PRIVILEGES ON DATABASE sonarqube TO sonarqube;
```

Altere ara a base `sonarqube`

```bash
postgres=# \c sonarqube
```

Output:
```bash
You are now connected to database "sonarqube" as user "postgres".
```

Atribua os privilégios do usuário ao schema public.

```bash
postgres=# GRANT ALL PRIVILEGES ON SCHEMA public TO sonarqube;
```

Saida do cli

```bash
postgres=# \q
```


## Nginx

Utilizaremos o NGINX como font end da console web

Importe a chave do repositório
```bash
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg]  http://nginx.org/packages/mainline/ubuntu/ `lsb_release --codename --short` nginx" > /etc/apt/sources.list.d/nginx.list
```

Crie o arquivo de config do repo
```bash
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
```

Instale o Nginx
```bash
apt update
apt install -y nginx
apt install -y nginx-extras # precisa ser em comando separado
```

### Configurando o NGINX

Edite o arquivo `/etc/nginx/nginx.conf` conforme abaixo:

Lembre de verificar o parâmetro `user` para manter o mesmo usuário.

```bash
nginx_user=$(cat /etc/nginx/nginx.conf | grep -E '\buser\b' | sed 's/user//g;s/\;//g' | tr -d ' ')
echo "Nginx User: $nginx_user"
```

```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log  /var/log/nginx/error.log warn;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections  1024;
    # multi_accept on;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    limit_conn_zone $binary_remote_addr zone=addr:10m;
    server_names_hash_bucket_size  256;

    client_max_body_size 10m;

    log_format log_standard '$remote_addr, $http_x_forwarded_for - $remote_user [$time_local] "$request_method $scheme://$host$request_uri $server_protocol" $status $body_bytes_sent "$http_referer" "$http_user_agent" to: $upstream_addr';

    access_log /var/log/nginx/access.log log_standard;
    error_log /var/log/nginx/error.log;

    sendfile        on;
    #tcp_nopush     on;
    server_tokens off; # removed pound sign
    more_set_headers 'Server: StrataSec';
    
    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
```

Crie o arquivo `/etc/nginx/conf.d/sonarqube.conf` conforme abaixo

```
server {
    listen        80;
    server_name   _;

    root /dev/null;
    index index.html index.htm;
    try_files $uri $uri/ $uri/404 =404;

    client_max_body_size 100000M;

    location / {

        proxy_set_header    Host                $host;
        proxy_set_header    X-Real-IP           $remote_addr;
        proxy_set_header    X-Forwarded-For     $remote_addr;
        proxy_set_header    X-Forwarded-Proto   $scheme;

        proxy_ssl_verify       off;

        proxy_buffer_size 8k;
        proxy_buffering on;
        proxy_buffers 8 8k;
        proxy_busy_buffers_size 16k;
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:9000;

    }

    error_page 403 /403.txt;
    location /403.txt{
        internal;
        return 403 'Forbidden';
    }

}
```

Remova o arquivo padrão

```
rm -rf /etc/nginx/conf.d/default.conf
```

Habilite o serviço do nginx

```
systemctl enable nginx
systemctl start nginx
```


## Configs gerais do sistema operacional

### Log de erro multipathd

Dependendo da infra você verá constantemente no syslog o erro abaixo

```
Apr 12 19:03:41 webdev multipathd[736]: sda: add missing path
Apr 12 19:03:41 webdev multipathd[736]: sda: failed to get udev uid: Invalid argument
Apr 12 19:03:41 webdev multipathd[736]: sda: failed to get sysfs uid: Invalid argument
Apr 12 19:03:41 webdev multipathd[736]: sda: failed to get sgio uid: No such file or directory
```

Caso isso esteja ocorrendo edite o arquivo `/etc/multipath.conf` adicionando as seguintes linhas

```
defaults {
    user_friendly_names yes
}
blacklist {
    devnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st|sda)[0-9]*"
}
```

Posteriormente reinicie o serviço

```bash
/etc/init.d/multipath-tools restart
```

### Locales

Para que o python possa funcionar em outros locales é necessário instalar

```
locale-gen en_US
locale-gen en_US.utf8
locale-gen pt_BR
locale-gen pt_BR.UTF-8
echo 'LANG="en_US.UTF-8"' > /etc/default/locale
echo 'LANGUAGE="en_US:en"' >> /etc/default/locale
echo 'LC_ALL="en_US.UTF-8"' >> /etc/default/locale
```

### Gestão de logs

Um item interessante pata otimizar e gerir os logs é o processo de logrotate, para isso faremos algumas configurações

Edite o arquivo `/etc/logrotate.conf` e adicione a linha abaixo

```
dateext
```

Edite os arquivos abaixo mantendo a seguinte configuração para todos eles:

```
rotate 365
daily
missingok
notifempty
delaycompress
compress
dateext
```

Arquivos a serem ajustados
- /etc/logrotate.d/rsyslog
- /etc/logrotate.d/nginx

### Sincronização de data/hora

Etapa 1: lista de fusos horários disponíveis
    
```
timedatectl list-timezones
```

Etapa 2: definir o fuso horário desejado
  
```
timedatectl set-timezone America/Sao_Paulo
```

### Configurar o NTP

Sincronize o relógio do sistema com o servidor a.ntp.br manualmente (use este comando apenas uma vez, ou conforme necessário):
  
```bash
service ntp stop
ntpdate a.ntp.br
service ntp start
```


## Sonar

```bash
apt install openjdk-17-jre openjdk-17-jdk unzip zip curl jq
```

Verificar versão do java

```bash
java -version
```

Output
```
openjdk version "17.0.16" 2025-07-15
OpenJDK Runtime Environment (build 17.0.16+8-Ubuntu-0ubuntu122.04.1)
OpenJDK 64-Bit Server VM (build 17.0.16+8-Ubuntu-0ubuntu122.04.1, mixed mode, sharing)
```

Verifique a ultima release do SonarQube em [SonarQube releases page](https://binaries.sonarsource.com/?prefix=Distribution/sonarqube/). em Nosso caso utilizaremos a `sonarqube-25.9.0.112764.zip`.

Realize o donwload deste arquivo

```bash
cd /opt/
curl -LO https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-25.9.0.112764.zip
```

Extraia o arquivo zip
```bash
unzip sonarqube-25.9.0.112764.zip
```

Mova o conteúdo descompactado para o diretório final da instalação
```bash
sudo mv sonarqube-25.9.0.112764/ /opt/sonarqube
```

**Nota:** O  SonarQube não pode ser executado como `root` então será necessário criar um usuário para execução. Desta forma criaremos um usuário sem diretório home e sem permissão de login.


```bash
adduser --system --no-create-home --group --disabled-login --gecos "" sonarqube
```

Defina as permissões do diretório `/opt/sonarqube` para o usuário

```bash
sudo chown -R sonarqube:sonarqube /opt/sonarqube
```

### Configure SonarQube

Edite o arquivo `/opt/sonarqube/conf/sonar.properties` adicionando as linhas abaixo:

```
sonar.jdbc.username=sonarqube
sonar.jdbc.password=MySuperSecretPassword
sonar.jdbc.url=jdbc:postgresql://localhost:5432/sonarqube
sonar.web.javaAdditionalOpts=-server
sonar.web.host=127.0.0.1
sonar.web.port=9000
```

Crie o arquivo `/etc/sysctl.d/99-sonarqube.conf`  com o seguinte conteudo:

```
vm.max_map_count=524288
fs.file-max=131072
```

Que definirá as seguintes configurações:

- **vm.max_map_count=524288**: Aumenta o número de mapeamentos de memória que o Elasticsearch pode usar, permitindo lidar com grandes volumes de dados.
- **fs.file-max=131072**: Aumenta o número máximo de arquivos que o Elasticsearch pode abrir, permitindo que ele seja executado de forma eficiente.

O SonarQube utiliza o Elasticsearch para armazenar índices em um sistema de arquivos com memória mapeada. Ajustar os limites do sistema para mapeamento de memória virtual e manipulação de arquivos garante maior estabilidade e desempenho do SonarQube.

Crie um novo arquivo `/etc/security/limits.d/99-sonarqube.conf` para configurar os limites de recursos do SonarQube:

```
sonarqube   -   nofile   131072
sonarqube   -   nproc    8192
```

Dentro dessa configuração:

- **nofile=131072**: Aumenta o número de descritores de arquivos abertos, permitindo ao SonarQube lidar com grandes cargas de trabalho.
- **nproc=8192**: Eleva o limite de processos para evitar falhas sob alta concorrência.


### Configurando SonarQube como serviço

Crie um novo arquivo `/etc/systemd/system/sonarqube.service` com o seguinte conteúdo:

```
[Unit]
Description=SonarQube service
After=syslog.target network.target

[Service]
Type=forking

ExecStart=/opt/sonarqube/bin/linux-x86-64/sonar.sh start
ExecStop=/opt/sonarqube/bin/linux-x86-64/sonar.sh stop

User=sonarqube
Group=sonarqube
PermissionsStartOnly=true
Restart=always

StandardOutput=syslog
LimitNOFILE=131072
LimitNPROC=8192
TimeoutStartSec=5
SuccessExitStatus=143

[Install]
WantedBy=multi-user.target
```

Recarrege as configurações do Systemd, habilite e inicie o serviço
```bash
systemctl daemon-reload
systemctl enable sonarqube
systemctl start sonarqube
```


### Access SonarQube

Acesse o SonarQube utilizando o IP do seu servidor ou o nome de domínio.

Faça login no SonarQube com as seguintes credenciais quando solicitado:

- Usuário: admin
- Senha: admin

## Realizando Scan local

### Crie um projeto

[![]({{site.baseurl}}/assets/2025/09/eb2f9516f93f814160f2e6f58eeec7d7.png)]({{site.baseurl}}/assets/2025/09/eb2f9516f93f814160f2e6f58eeec7d7.png)

[![]({{site.baseurl}}/assets/2025/09/b93bf3b06a9a9b33b64aa67edf4572fe.png)]({{site.baseurl}}/assets/2025/09//b93bf3b06a9a9b33b64aa67edf4572fe.png)

[![]({{site.baseurl}}/assets/2025/09/8602613239133af6af85f3f5d6f5e02e.png)]({{site.baseurl}}/assets/2025/09/8602613239133af6af85f3f5d6f5e02e.png)

[![]({{site.baseurl}}/assets/2025/09/17c62eee77cbb08a28dee918d998987f.png)]({{site.baseurl}}/assets/2025/09/17c62eee77cbb08a28dee918d998987f.png)

[![]({{site.baseurl}}/assets/2025/09/cb1cbb2c9b273b0ef6855170d90bfc9c.png)]({{site.baseurl}}/assets/2025/09/cb1cbb2c9b273b0ef6855170d90bfc9c.png)

[![]({{site.baseurl}}/assets/2025/09/f1ff19e7675f7e648681c7f0f79d270d.png)]({{site.baseurl}}/assets/2025/09/f1ff19e7675f7e648681c7f0f79d270d.png)


### Analise utilizando uma imagem Docker

A imagem Docker torna-se versátil por poder ser utilizada em qualquer sistema operacional sem a necessidade de instalação de diversas ferramentas.

```bash
docker pull sonarsource/sonar-scanner-cli:latest

docker run \
--rm \
-e SONAR_TOKEN="sqp_558e1dfb9c..." \
-e SONAR_HOST_URL="https://${SONAR_HOST_URL}"  \
-v "${PROJECT_BASEDIR}:/usr/src" \
sonarsource/sonar-scanner-cli -Dsonar.projectKey=projeto-exemplo
```

## Links

Fonte: https://docs.sonarsource.com/sonarqube-server/9.8/setup-and-upgrade/install-the-server

Pré-requisitos: 
https://docs.sonarsource.com/sonarqube-server/9.8/requirements/prerequisites-and-overview





