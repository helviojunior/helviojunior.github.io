---
layout: post
title: Localizando IPs que respondem para uma URL
date: 2024-10-31 20:00:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Offensive Security
tags:
- Offensive Security
- WAF
- Bypass WAF
- Pentest
author: Helvio Junior (m4v3r1ck)
permalink: "/security/osint/localizando-ips-que-respondem-para-uma-url/"
excerpt: "Realize o Bypass do WAF utilizando o Web Finder para localizar endereços que respondem pelo site sem WAF"
image:
  src: /assets/2024/10/e52cfdb1d4783a4b933ba33b548f54a4.png
  alt: Web Finder
---

## Introdução

O Web Finder tem por objetivo auxiliar na localização de endereços IP que respondem por uma URL específica, podendo, desta forma ocorrer o Bypass do WAF.

## Conceito técnico
Ao realizar uma requisição HTTP/S para um host a primeira fase a ser realizada pelo cliente é a resolução de nome para IP e posteriormente conexão direta para este IP. Este procedimento se refere até a camada de Transporte do modelo OSI (camada 4) onde temos apenas IP e porta. Após a conexão TCP ocorrer com sucesso o cliente monta um cabeçalho de requisição HTTP e envia ao servidor, veja o exemplo a seguir:

Supondo que em um navegador seja digitado https://www.helviojunior.com.br (conforme o comando curl abaixo), primeiramente o cliente resolverá o nome DNS para o IP (cujo resultado será 54.244.151.52) e posteriormente enviará o cabeçalho conforme abaixo:

```bash
curl -k https://www.helviojunior.com.br
```

Cabeçalho:

```
GET / HTTP/1.1
Host: www.helviojunior.com.br
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close
```

Como podemos observar no cabeçalho `Host` temos o nome completo do servidor. Com o advento do HTTP 1.1 em diante o servidor leva em consideração este campo para rotear internamente em qual site deve responder, sendo que se o servidor estiver preparado para responder por este host (www.helviojunior.com.br) o mesmo o fará.

Porém nós podemos realizar o mesmo processo de forma diferente, onde direcionamos o cliente em qual endereço IP o mesmo deve conectar e forçamos o host no cabeçalho do HTTP conforme o comando abaixo:

```bash
curl -k -H 'Host: www.helviojunior.com.br' https://54.244.151.52
```

Deste modo obrigatoriamente a conexão TCP ocorrerá para o IP 54.244.151.52 independente da resolução DNS, porém no cabeçalho http será enviado o host www.helviojunior.com.br. Desta forma iremos obter o mesmo resultado como resposta.

Porém deste modo podemos alterar o endereço IP para qualquer outro, como por exemplo 10.10.10.10 que de o servidor deste IP existir e tiver preparado para responder ao site www.helviojunior.com.br a resposta (HTTP Status code e tamanho) será a mesma.

```bash
curl -k -H 'Host: www.helviojunior.com.br' https://10.10.10.10
```

> Porém, no cenário acima o `Subject Name` informado via `SNI` será o IP ao invés do `host`, sendo assim em cenários onde o TLS exige SNI o comando acima não irá funcionar, desta forma precisaremos utilizar outra estratégia.
{: .prompt-warning }


Para isso utilizaremos o parâmetro `--resolve [DOMAIN]:[PORT]:[IP]` do CURL

```bash
curl -k --resolve www.helviojunior.com.br:443:54.244.151.52 https://www.helviojunior.com.br
```

Deste modo, igualmente no cenário anterior, obrigatoriamente a conexão TCP ocorrerá para o IP 54.244.151.52 pois o parâmetro `--resolve` ignora a resolução de nome via DNS. Adicionalmente desta forma o cabeçalho `host` e o `Subject Name` do `SNI` serão definidos corretamente.

Sendo assim podemos utilizar essa técnica para passar uma lista de IPs e verificar se eles estão configurados para responder por um determinado site.

## Instalação

### Instalando pipx

> Recomendamos a utilização do `pipx` ao invés do `pip` para instalação no sistema.
{: .prompt-warning }

```bash
python3 -m pip install pipx
python3 -m pipx ensurepath
```

### Instalando do Web Finder

```bash
python3 -m pipx install wafwebfinder
```


## Exemplo prático

Para este tutorial realizaremos o teste com o serviço do X (antigo Twitter). A motivação da escrolha se dá pelo fato do mesmo ter alterado recentemente o seu serviço para uma CDN evitando os bloqueios impostos no Brasil.

### Enumeração de IPs

O primeiro passo necessário é a coleta/enumeração de possíveis IPs, para este processo utilizaremos 3 técnicas diferentes:

1. Emumeração ativa por força bruta no DNS
2. Enumeração passiva através do Virus Total
3. Enumeração passiva através do Shodan

### EnumDNS

o `enumdns` é um script criado por mim e disponível em [https://github.com/helviojunior/libs/blob/master/python/enumdns.py](https://github.com/helviojunior/libs/blob/master/python/enumdns.py)

Realizando o download da SecList (wordlist que utilizaremos)

```bash
mkdir -p /usr/share/wordlists/
cd /usr/share/wordlists/
git clone https://github.com/danielmiessler/SecLists
```

```bash
cd ~
wget https://raw.githubusercontent.com/helviojunior/libs/master/python/enumdns.py
python3 enumdns.py -d x.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o enumdns.txt
```

[![]({{site.baseurl}}/assets/2024/10/190a4c7725bd4eced57d42c1e62a331c.png)]({{site.baseurl}}/assets/2024/10/190a4c7725bd4eced57d42c1e62a331c.png)

> Mantenha o arquivo gerado `enumdns.txt` para que posteriormente possamos filtrar os IPs
{: .prompt-tip }

### Virus Total

Acesse o [VirusTotal](https://www.virustotal.com/) e digite a URL desejada, realize a busca e posteriormente clique em **Relations**.

[![]({{site.baseurl}}/assets/2024/10/77d12c98a1c531556aba5b6932152307.png)]({{site.baseurl}}/assets/2024/10/77d12c98a1c531556aba5b6932152307.png)

Na aba **Relations** teremos diversos endereços IPs

[![]({{site.baseurl}}/assets/2024/10/aabac0b30c726f5f712a93d426f1b351.png)]({{site.baseurl}}/assets/2024/10/aabac0b30c726f5f712a93d426f1b351.png)

Selecione todo o texto/html do site, copie e cole em um arquivo texto.

> Não se importe se vier outros textos neste processo, pois futuramente iremos filtrar somente os endereços IP
{: .prompt-tip }

[![]({{site.baseurl}}/assets/2024/10/4444a223d6c4a4d00fd6e31befb70836.png)]({{site.baseurl}}/assets/2024/10/4444a223d6c4a4d00fd6e31befb70836.png)

### Shodan

Visualize todos os endereços listados pelo Shodan através da URL `https://www.shodan.io/domain/{DOMAIN}`, substituindo o texto `{DOMAIN}` pelo domínio desejado. Exemplo: `https://www.shodan.io/domain/x.com`

[![]({{site.baseurl}}/assets/2024/10/618f3f3a0794120172d8cc00c2f80aa2.png)]({{site.baseurl}}/assets/2024/10/618f3f3a0794120172d8cc00c2f80aa2.png)

Selecione todo o texto/html do site, copie e cole em um arquivo texto.

> Não se importe se vier outros textos neste processo, pois futuramente iremos filtrar somente os endereços IP
{: .prompt-tip }


[![]({{site.baseurl}}/assets/2024/10/37a2c22f6076173c08a89280b5904a8d.png)]({{site.baseurl}}/assets/2024/10/37a2c22f6076173c08a89280b5904a8d.png)


### Filtrando somente os IPs

Salve todo o conteúdo obtido anteriormente em um único arquivo de texto.

Para fins de ilustração segue um comando `grep` para filtrar somente as linhas com endereçamento IPv4.

[![]({{site.baseurl}}/assets/2024/10/e60c561c311d427950957071b85c32ae.png)]({{site.baseurl}}/assets/2024/10/e60c561c311d427950957071b85c32ae.png)


```bash
cat tmp.txt | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
```

Agora vamos obter os endereços IP, ordena-los e filtrar por endereços únicos.


```bash
cat tmp.txt | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > tst.txt
```

[![]({{site.baseurl}}/assets/2024/10/d15cfa665415a650552fbe06a6a90514.png)]({{site.baseurl}}/assets/2024/10/d15cfa665415a650552fbe06a6a90514.png)

## Expandindo a busca

Em alguns cenários se faz necessário expandir a busca para todas as subnets `/24` dos IPs encontrados. 

> Este passo não é obrigatório, mas pode ser importante para expandir a busca e encontrar outros endereçamentos que não foram listados nos passos anteriores. Em ambiente clould certamente virá bastante IP que possivelmente não faz parte do escopo do teste, mas em ambiente on-premisses a acertividade é bem alta.
{: .prompt-tip }

Para isso vamos extrair somente as subnets:

```bash
for net in $(cat *.txt | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.'):; do echo "${net}0/24"; done | sort -u > subnets.txt
```

Posteriormente realizar um NMAP para localizar os endereços que respondem por HTTP e HTTPS.

```bash
nmap -Pn -v -T4 -sTV -p80,443 -iL subnets.txt | tee -a nmap_subnets_1.txt
```

Após a finalização podemos filtrar os endereços

```bash
cat nmap_subnets_1.txt | grep 'open port' | grep '443\|80' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > tst.txt
```

## Utilizando o WebFinder

Agora que temos uma lista de IPs, podemos utiliza-la para verificar quais servidores respondem pelo serviço desejado.

```bash
webfinder -t https://x.com/ -ip tst.txt -o x.txt --random-agent
```

> O comando acima irá respeitar o protocolo estipulado pela URL `http` ou `https`. Caso deseje realizar a busca em ambos protocolos basta utilizar o parâmetro `--check-both`
{: .prompt-tip }

### Blind check

O Web Finder em seu modo de busca padrão, primeiramente irá se conectar ao site original e obter o código de retorno bem como o tamanho do corpo da resposta, este processo tem por objetivo entender o padrão do site original para posteriormente buscar pelo mesmo padrão diretamente nos endereços IP informados. 

Porém existem alguns cenários onde o acesso ao site original não é possível, por diversas razões, como bloqueio, conectividade de rede e etc... Nestes casos o Web Finder detém de um parâmetro `--static` onde é possível a parametrização do código de retorno (Ex: 200, 204, 404, 500 e etc...) em conjunto (ou não) com o tamanho da resposta esperada.

Adotando como base a requisição anterior que obtivemos o código de retorno `200` com o tamanho de `2610 bytes` podemos realizar a execução com 2 variantes:

1. Somente o status code: `webfinder -t https://x.com/ -ip tst.txt -o x.txt --random-agent --static 200`
2. Status code + tamanho: `webfinder -t https://x.com/ -ip tst.txt -o x.txt --random-agent --static 200:2610`


[![]({{site.baseurl}}/assets/2024/10/1b37ddb9f2e6a31e014c213e3dcd93da.png)]({{site.baseurl}}/assets/2024/10/1b37ddb9f2e6a31e014c213e3dcd93da.png)

[![]({{site.baseurl}}/assets/2024/10/08b7be65907ca0cd20412d6525e3bd40.png)]({{site.baseurl}}/assets/2024/10/08b7be65907ca0cd20412d6525e3bd40.png)

> A utilização do `--static` com somente o código de retorno pode acarretar em falso-positivo, uma vez que a identificação do retorno pode não ser precisa.
{: .prompt-warning }

## Conclusão

Como pudemos ver neste artigo, é possível obter os endereços IPs que respondem por um deternimado serviço. 

Adicionalmente a ferramenta `webfinder` apois neste processo e ilustra caso o IP endontrado esteja protegido por alguma ferramenta de CDN e/ou WAF.


[![]({{site.baseurl}}/assets/2024/10/5ac920de9474360e1ecbb465869b3c2d.png)]({{site.baseurl}}/assets/2024/10/5ac920de9474360e1ecbb465869b3c2d.png)


## Referencias:

- [Código fonte](https://github.com/helviojunior/webfinder)
- [PyPi - Python Package Index](https://pypi.org/project/WafWebFinder/)





