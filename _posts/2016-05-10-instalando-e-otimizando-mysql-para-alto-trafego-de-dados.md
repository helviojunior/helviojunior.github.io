---
layout: post
title: Instalando e otimizando o MySQL para alto tráfego de dados
date: 2016-05-10 12:40:24.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- MySQL
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/mysql/instalando-e-otimizando-mysql-para-alto-trafego-de-dados/"
---

Na maioria dos ambientes onde é instalado o MySQL não se tem configurações mínimas para um alto desempenho do banco de dados. Neste post não pretendo abordar 100% das técnicas, recursos e tecnologias que poderiam ser utilizadas para otimizar o MySQL, mas sim abordar configurações simples mas muito eficazes para otimização do MySQL.

<!--more-->De modo geral as configurações aqui propostas se baseiam na seleção de um bom sistema de arquivos para cada função do banco de dados, bem como otimização da configuração para utilizar todo potencial do hardware.

**ATENÇÃO!!!! Ao realizar qualquer operação em banco de dados que esteja em produção tenha certeza que você tem backup dos seus dados, pois este procedimento excluirá todas as informações da base de dados. Qualquer perda de dados é por sua conta e risco.**

## Atualização do sistema

Antes de qualquer instalação é interessante garantir que nosso sistema está atualizado, faça isso com os comandos abaixo

```bash
apt-get update
apt-get upgrade
```

## Remoção de instalações antigas

O primeiro passo antes de instalar uma nova instalação do MySQL é necessário desinstalar uma versão atual. Gostaria de frisar mais uma vez que este processo apagará todos os dados atuais do seu banco de dados então, tenha certeza de que você tem um backup integro da sua base dedados, pois não me responsabilizo por eventuais perdas de dado em seu ambiente.

```bash
apt-get remove --purge mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-*
rm -rf /etc/mysql /var/lib/mysql/*
apt-get autoremove
apt-get autoclean
```

## Preparando o ambiente, partições, diretórios e sistema de arquivos

Antes de iniciar a instalação do MySQL propriamente dita vamos criar as partições, formatar e montar em uma estrutura de diretório específica para o banco de dados.

Instale as dependências necessárias

```bash
apt-get install libaio1 libaio-dev xfsprogs libc6
```

Utilizando o aplicativo de sua preferência, crie 4 partições no disco secundário. As partições devem ser criadas com os tamanhos ajustados para o seu ambiente, para termos um norte segue abaixo uma tabela com a sugestão de tamanho a ser utilizado e a função de cada uma das partições.

Obviamente essa é somente uma tabela de sugestão pois diversas coisas irão influenciar na montagem dessa tabela, como quantidade de transações, tamanho da base, o que será armazenado em log e etc...

| **Partição** | **Função** | **Espaço sugerido** |
| --- | --- | --- |
| 1 | Armazenamento das bases de dados | 85% do disco |
| 2 | Armazenamento de logs (Innolog) para rollback, reciperação de desastres e etc... | 5% do disco |
| 3 | Armazenamento de logs (bin) para replicação e backup incremental | 5% do disco |
| 4 | Diretório temporário | 5% do disco |

Suponto que o seu disco é de 100Gb e que o mesmo esteja fisicamente no **/dev/sdb** monte as 4 partições que ficarão da seguinte forma: **/dev/sdb1**, **/dev/sdb2**, **/dev/sdb3** e **/dev/sdb4**.

Formate o disco com os comandos abaixo, apenas trocando **/dev/sdbX** para o nome real do seu disco

```bash
mkfs.xfs -f -d agcount=256 -l size=128m,lazy-count=1,version=2 -L mysql_bases /dev/sdb1
mkfs.ext2 -m0 -L mysql_innolog /dev/sdb2
mkfs.ext2 -m0 -L mysql_binlog /dev/sdb3
mkfs.ext2 -m0 -L mysql_tmpdir /dev/sdb4
```

Localize o UUID da sua partição

```bash
ls -l /dev/disk/by-uuid
```

[![uuid-mysql]({{ site.baseurl }}/assets/2016/05/uuid-mysql.png)]({{ site.baseurl }}/assets/2016/05/uuid-mysql.png)

Edite o arquivo **/etc/fstab** e adicione as linhas abaixo, utilizando o UUID do seu disco, para que o seu disco seja montado na inicialização

```bash
UUID=71ce0a1a-cff9-4ade-985c-aaf4bfabd7f9 /u01/mysql/bases/ xfs allocsize=256m,logbufs=8,noatime,nobarrier,nodiratime,attr2,logbsize=256k 0 0
UUID=ad22e209-08b4-405c-9c6b-7ac9da2e4376 /u01/mysql/innolog/ ext2    errors=remount-ro,noatime,nodiratime,rw 0 0
UUID=f08fabbd-5ac5-41cb-9c8e-ad9f01492d88 /u01/mysql/binlog/ ext2    errors=remount-ro,noatime,nodiratime,rw 0 0
UUID=3b7f233a-cdbb-44a1-9d60-d878af3ea7e4 /u01/mysql/tmpdir/ ext2    errors=remount-ro,noatime,nodiratime,rw 0 0
```

Crie os diretórios que serão utilizados pelo banco de dados

```bash
mkdir -p /u01/mysql/bases/
mkdir -p /u01/mysql/innolog/
mkdir -p /u01/mysql/tmpdir/
mkdir -p /u01/mysql/logs/
mkdir -p /u01/mysql/binlog/relay
```

Adicione o usuário e grupo do mysql

```bash
groupadd mysql
useradd -r -g mysql mysql
```

Monte todos os apontamentos realizados no fstab

```bash
mount -a
```

Crie o arquivo de logs

```bash
touch /u01/mysql/logs/error.log
```

Altere as permissões dos diretórios montados e arquivos

```bash
chown -R mysql:mysql /u01
chmod -R 755 /u01/mysql/
```

Realize algumas otimizações do sistema operacional, bem como a criação de algumas variáveis de ambiente com os comandos abaixo

```bash
echo "PATH=$PATH:/usr/local/mysql/bin" >> /etc/profile.d/mysql
echo "PATH=$PATH:/usr/local/mysql/bin" >> /etc/environment
echo "mysql soft nofile 1048576" >> /etc/security/limits.conf
echo "mysql hard nofile 1048576" >> /etc/security/limits.conf
echo "# --- MySQL Install --- " >> /etc/sysctl.conf
echo "vm.swappiness = 1" >> /etc/sysctl.conf
echo "net.core.rmem_default = 33554432" >> /etc/sysctl.conf
echo "net.core.rmem_max = 33554432" >> /etc/sysctl.conf
echo "net.core.wmem_default = 33554432" >> /etc/sysctl.conf
echo "net.core.wmem_max = 33554432" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem = 10240 87380 33554432" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem = 10240 87380 33554432" >> /etc/sysctl.conf
echo "net.ipv4.tcp_no_metrics_save = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_window_scaling = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_sack = 1" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 5000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_mem = 786432 1048576 26777216" >> /etc/sysctl.conf
echo "net.ipv4.ip_local_port_range = 1024 65535" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_tw_buckets = 360000" >> /etc/sysctl.conf
echo "fs.nr_open = 1048576" >> /etc/sysctl.conf
echo "mysql soft nofile 1048576" >> /etc/security/limits.conf
echo "mysql hard nofile 1048576" >> /etc/security/limits.conf
export PATH=$PATH:/usr/local/mysql/bin
```

Caso a distribuição do seu Linux seja RedHat ou Centos, é necessário executar o comando abaixo para desativar o SELINUX

```bash
sed 's/SELINUX=enforcing/SELINUX=disabled/g ' -i /etc/selinux/config
reboot
```

## Instalando o MySQL

Realize o download e descompactação do MySQL com os comandos abaixo

```bash
wget http://cdn.mysql.com/archives/mysql-5.6/mysql-5.6.37-linux-glibc2.12-x86_64.tar.gz
tar -zxvf mysql-5.6.37-linux-glibc2.12-x86_64.tar.gz -C /usr/local
ln -sf /usr/local/mysql-5.6.37-linux-glibc2.12-x86_64 /usr/local/mysql
```

Copie o script de inicialização do MySQL

```bash
cp /usr/local/mysql/support-files/mysql.server /etc/init.d/mysql
```

Edite o arquivo **/etc/init.d/mysql** alterando as linhas conforme exemplo abaixo

```bash
basedir=/usr/local/mysql
datadir=/u01/mysql/bases
```

Crie o arquivo **/u01/mysql/my.cnf**  com o conteúdo abaixo

```bash
## Helvio Junior – my.cnf template
### my.cnf

[client]
port            = 3306
socket          = /u01/mysql/mysql.sock

[mysqld_safe]
open_files_limit = 1024000
basedir        = /usr/local/mysql
timezone        = America/Sao_Paulo
socket          = /u01/mysql/mysql.sock
nice            = 0

# Diretório de logs e consultas lentas
log-error       = /u01/mysql/logs/error.log
pid-file        = /u01/mysql/bases/mysql.pid

[mysqld]
open_files_limit = 1024000
general_log     = 0
log_warnings    = 1
general_log_file = /u01/mysql/logs/mysqld.log
log-error       = /u01/mysql/logs/error.log
log-slow-admin-statements = 0
explicit_defaults_for_timestamp = 1

#Consultas lentas
slow_query_log			= 1
slow_query_log_file		= /u01/mysql/logs/mysql-slow.log
long_query_time			= 5

#Consultas sem indices
log-queries-not-using-indexes = 0

user            = mysql
pid-file        = /u01/mysql/bases/mysql.pid
socket          = /u01/mysql/mysql.socket
port            = 3306
basedir        = /usr/local/mysql
datadir         = /u01/mysql/bases/
tmpdir          = /u01/mysql/tmpdir
lc-messages-dir = /usr/local/mysql/share/

# Performance Analsys
performance_schema = off

# Desativa o LOAD FILE
local-infile = 0
old_passwords=0

# 0x = MASTER
# 1x = Slave Level 1
# 2x = Slave em baixo de Slave
server-id=01

# Master Setup (Caso tenha replicação)
#binlog_format = ROW
#log-bin        = /u01/mysql/binlog/mysql-bin
#log_slave_updates = 1
#log_bin_trust_function_creators = 1
#expire_logs_days = 1

# Configuracoes Diversas
#Compatibilidade
sql_mode = ''

skip-name-resolve
max_connections = 10000
query_cache_size = 80M
query_cache_min_res_unit = 2K
query_cache_type = 1
sort_buffer_size = 2M
read_buffer_size = 128k
join_buffer_size = 5M
myisam_sort_buffer_size = 128M
bulk_insert_buffer_size = 128M
max_allowed_packet = 1G
thread_cache_size = 100

# Tabelas temporárias
# Configura o tamanho maximo para tabela do tipo MEMORY
max_heap_table_size = 1G

# Configura o tamanho maximo antes de converter para MyISAM
tmp_table_size = 1G

# Federated Store Engine
federated

# InnoDB (Default)

# Depreciado na 5.6 - Armazena dicionario de dados na ram
innodb_additional_mem_pool_size = 16M

# BUFFER POOL
#

# Alterar este valor para +- 80 da memória do servidor
innodb_buffer_pool_size = 1G

# Segregacao do buffer_pool - Performance para algoritmo LRU (qtd cpu)
innodb_buffer_pool_instance = 6

# Redo Log
innodb_log_buffer_size = 1G
innodb_log_group_home_dir = /u01/mysql/innolog
innodb_log_files_in_group = 7
innodb_log_file_size = 512M

# Manipulacao de arquivos
innodb_open_files = 1024000
innodb_file_per_table = 1
innodb_data_file_path = ibdata1:1G:autoextend
innodb_data_home_dir=/u01/mysql/bases/

# O_DIRECT para fazer by-pass (O EBS controla)
innodb_flush_method = O_DIRECT
innodb_file_format = BARRACUDA

# QTD de IOPS que esta disponível para o datadir
innodb_io_capacity = 1000

# Controle Transacional
transaction-isolation=READ-COMMITTED
innodb_support_xa = 0

# Qtd de segundos antes de um Lock wait timeout exceeded
innodb_lock_wait_timeout = 120
```

Altere o parâmetro **innodb_buffer_pool_size** deste arquivo recém criado para um valor de +- 80% da memória do ser servidor.

Crie um link simbólico do arquivo de configuração para o diretório /etc

```bash
ln -s /u01/mysql/my.cnf /etc/my.cnf
```

Crie as bases de dados iniciais do MySQL

```bash
cd /usr/local/mysql
scripts/mysql_install_db --datadir=/u01/mysql/bases/ --basedir=/usr/local/mysql
```

Configure para que o MySQL inicie automaticamente na inicialização do sistema operacional e inicie o serviço

```bash
update-rc.d -f mysql defaults
service mysql start
```

Por questões de segurança, altere a senha padrão do usuário root do banco de dados

```bash
/usr/local/mysql/bin/mysqladmin -u root password 'new-password'
```

Pronto, o seu servidor de MySQL está instalado e pronto para uso.

Caso deseje outras otimizações não citadas neste post segue uma sugestão se referência para consulta: [http://blog.neweb.co/pt/how-to-optimize-a-mysql-server/](http://blog.neweb.co/pt/how-to-optimize-a-mysql-server/)
