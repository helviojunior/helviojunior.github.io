---
layout: post
title: Clareza e produtividade na gestão do Firewall Aker 6.1
date: 2012-03-07 02:29:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Artigos acadêmicos
- Segurança da Informação
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/clareza-e-produtividade-na-gestao-do-firewall-aker-6-1/"
---

Este post é a publicação do meu trabalho de conclusão de curso de Especialização em Redes e Segurança de Sistemas realizado na Pontifícia Universidade Católica do Paraná em março de 2010

Este estudo objetiva demonstrar o ganho de produtividade e clareza na gestão da segurança periférica corporativa, utilizando o Aker Firewall. A motivação inicial deste estudo baseia-se na dificuldade de se encontrar um padrão metodológico de implementação dos recursos de segurança periférica em produtos Linux e de se ter o nível técnico e o tempo necessários para a gestão dessas atividades.

<!--more-->

# 1.      Conceitos relacionados

## 1.1. A segurança da informação

Quando se fala em segurança de informação, é imprescindível entender, primeiramente, o que é informação e qual a sua importância para a empresa. A definição desse termo nem sempre é a mesma nas diversas áreas de trabalho, mas há semelhanças que são difundidas.

Uma delas, é a figura a seguir intitulada “pirâmide do conhecimento”:

[![Pirâmide do conhecimento]({{ site.baseurl }}/assets/2012/03/low_image1-300x291.jpg)]({{ site.baseurl }}/assets/2012/03/low_image1-300x291.jpg)

Figura1: Pirâmide do conhecimento

Nessa representação, baseada na pirâmide de DUSSIN E FERRO (2009), ―dado‖ seria “como uma seqüência de símbolos quantificados ou quantificáveis. Nesse sentido, um texto contendo letras, que são símbolos de um conjunto finito que é o alfabeto, pode constituir-se de uma base numérica e portanto é um dado. Também são dados, as fotos, as figuras, os sons gravados, pois todos podem ser quantificados.” SETZER (2002, p.1)

De acordo com CHIAVENATO (1999, p. 366), a “informação é um conjunto de dados com um significado, ou seja, que reduz a incerteza ou que aumenta o conhecimento a respeito de algo”.

Já o “conhecimento”, como definido por DAVENPORT (1998, p.19), “é a informação mais valiosa. É valiosa precisamente porque alguém deu à informação um contexto, um significado, uma interpretação”. A partir dessa definição, CAMPOS (2006, p. 3) afirma ainda que “a informação possui significado e causa impacto em grau menor ou maior, tornando-a o elemento essencial da extração e criação do conhecimento”. Dessa forma, o conhecimento pode ser considerado como a informação processada pelos indivíduos, ou seja, ele é adquirido pela utilização da informação na ação humana.

Portanto, a informação é de grande importância para a geração do conhecimento. Nesse viés, CAMPOS (2006, p.4) define a informação como um valor para o negócio devido a sua importância nas tomada de decisões, estando ligada diretamente à geração de lucro. Tornando-se, assim, um bem, um ativo da organização, e como tal devendo ser protegido e preservado.

Nesse escopo de proteção e preservação da informação, é importante definir e entender qual o significado de um sistema de segurança (proteção) da informação e quais são seus pilares e princípios que norteiam a implementação dessa prática.

A norma NBR ISO/IEC 27002/2005 conceitua a segurança da informação como sendo a “preservação da confidencialidade, da integridade e da disponibilidade da informação”. Conforme ilustrado na figura 2, a segurança da informação está baseada em três pilares: 1) confidencialidade, 2) integridade, 3) disponibilidade.

Essa norma afirma ainda que “adicionalmente, outras propriedades, tais como autenticidade, responsabilidade, não repúdio e confiabilidade, podem também estar envolvidas”.

[![Pilares da segurança da informação]({{ site.baseurl }}/assets/2012/03/low_image2.jpg)]({{ site.baseurl }}/assets/2012/03/low_image2.jpg)

Figura 2: Pilares da segurança da informação

Dessa forma, ao se quebrar um desses pilares, ocorre a quebra da segurança da informação ou, também chamada, incidente de segurança da informação.

Para se obter um entendimento melhor desses pilares e as outras propriedades propostas pela NBR ISO/IEC 27002/2005, será utilizada a definição de SÊMOLA (2003, p. 45), de NBR ISO/IEC 27002/2005 e de ISO/IEC 13335-1:2004.

**Confidencialidade:** toda informação deve ser protegida de acordo com o grau de sigilo de seu conteúdo, visando a limitação de seu acesso e uso apenas às pessoas para quem elas são destinadas.

**Integridade:** toda informação deve ser mantida na mesma condição em que foi disponibilizada pelo seu proprietário, visando protegê-las contra alterações indevidas, intencionais ou acidentais.

**Disponibilidade:** toda informação gerada ou adquirida por um indivíduo ou instituição deve estar disponível aos seus usuários no momento em que os mesmos dela necessitarem para qualquer finalidade.

**Autenticidade:** a garantia de que o usuário, objeto ou recurso é quem diz ser.

**Responsabilidade:** a capacidade de responsabilização de um usuário pelos atos cometidos.

**Não repúdio:** garantia de uma ação, evento ou informação não poderá ser negada pelo seu autor.

**Confiabilidade:** garantia de tolerância a falhas de um sistema de informação.

No contexto de segurança de informação, há vulnerabilidades, que são fraquezas presentes nos ativos[[1]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftn1) de informação e que podem causar, intencionalmente ou não, a quebra de um ou mais dos três princípios de segurança da informação. (CAMPOS, 2006, p. 9).

Podem-se relacionar as vulnerabilidades aos seguintes ativos de informação[[2]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftn2):

1. Tecnologias:
  1. Computadores sem proteção contra vírus, spywares e worms;
  2. Switches não protegidos com senha ou protegidos com a senha padrão de fábrica;
  3. Rede local acessível por senha padrão ou pública;
  4. Sistema de informação sem controle de acesso lógico;
  5. Acesso não controlado a recursos computacionais externos a rede corporativa (tendo como origem um equipamento interno).
2. Pessoas e processos:
  1. A ausência de uma política institucional de segurança da informação dentro da organização;
  2. A inexistência de regulamentação para acesso à informação da organização por terceiros e prestadores de serviço;
  3. A ausência de procedimentos disciplinares para o tratamento das violações da política de segurança da informação;
  4. A ausência de regulamentação explícita quanto aos cuidados com a informação, do que é permitido ou não, tais como os procedimentos de compra ou desenvolvimento de sistemas de informação, a gestão das cópias de segurança, controle de versão e software, proteção contra softwares maliciosos, gerenciamento da rede local de computadores, gestão das mídias de armazenamento, uso do correio eletrônico, acesso à Internet, entre outros.

Observa-se por essa breve relação que a segurança da informação não se limita no âmbito de informática, mas envolve toda a corporação.

## 1.2. Produtividade e clareza

### 1.2.1. Produtividade

A produtividade tem se tornado fator diferencial entre o manter-se no mercado ou sucumbir.

MACEDO (2002, p. 1) afirma que:

“Atualmente, sem produtividade ou sem a eficiência do processo produtivo, dificilmente uma empresa vai ser bem-sucedida ou até mesmo sobreviver no mercado. Dado o acirramento da concorrência, a gestão da produtividade está se tornando um dos quesitos essenciais na formulação das estratégias de competitividade das empresas”.

Um aumento de produtividade pode ser alcançado de várias maneiras, PARKINSON (2004, p. 1) listou 5 abordagens que podem ser aplicadas para o incremento de produtividade:

1. Eliminar trabalho desnecessário;
2. Eliminar retrabalho desnecessário;
3. Reduzir a duração do esforço;
4. Automatizar tudo que for possível; e
5. Gerenciar a demanda.

A Tecnologia da informação (doravante, TI) tem se mostrado uma importante ferramenta para o aumento de produtividade, inclusive englobando as 5 abordagens apontadas por PARKINSON.

### 1.2.2. Clareza

Segundo o dicionário MICHAELIS (2009), clareza é “qualidade do que é claro ou inteligível”, “qualidade do que se percebe bem” e ainda “limpidez, transparência”.

## 1.3. Protocolo de comunicação

O dicionário MICHAELIS (2009) conceitua protocolo como sendo o “conjunto de parâmetros que define como a transferência da informação vai ser controlada”. No entanto, antes de adentrarmos em detalhamentos técnicos dos protocolos de comunicação, observaremos a teoria básica da comunicação, conforme definida por JAKOBSON (2001, p. 14):

“A teoria da comunicação parece-me uma boa escola para a Lingüística estrutural, assim como a Lingüística estrutural é uma escola útil para os engenheiros de comunicações. Penso que a realidade fundamental com que se tem de haver o lingüista é a interlocução — a troca de mensagens entre emissor e receptor, entre remetente e destinatário, entre codificador e decodificador”.

JAKOBSON (2001) sugere, então, o seguinte esquema:

[![Teoria da comunicação]({{ site.baseurl }}/assets/2012/03/low_image3.jpg)]({{ site.baseurl }}/assets/2012/03/low_image3.jpg)

Figura 3: Teoria da comunicação

Observa-se na figura que toda comunicação é composta de uma fonte de dados que gera os dados de uma forma padrão, ou seja, em uma codificação, o emissor envia a mensagem ao receptor, que encaminha ao alvo (destino), que consegue interpretar estes dados por conhecer a codificação.

Esta teoria aplica-se de forma geral a todas as metodologias de comunicação existentes e na informática isso não é diferente. Para que haja comunicação entre dois ou mais computadores é necessário um código de comunicação, aqui chamado protocolo de comunicação.

O protocolo de comunicação mais utilizado em todo o mundo é o TCP/IP (Transfer Control Protocol / Internet Protocol).

### 1.3.1. TCP/IP

“O conjunto de protocolos TCP/IP foi desenvolvido como parte da pesquisa feita pela Defense Advanced Research Projects Agency (DARPA). Ele foi originalmente desenvolvido para fornecer comunicação através da DARPA. Posteriormente, o TCP/IP foi incluído com o Berkeley Software Distribution da UNIX. Agora, o TCP/IP é de fato o padrão das comunicações de internetworks e serve como protocolo de transporte para a Internet, permitindo a comunicação de milhares de computadores no mundo todo” (CISCO, 2000).

“A função da pilha, ou conjunto, TCP/IP é transferir informações de um dispositivo em rede para outro. Ao fazer isso, ela mapeia cuidadosamente o modelo de referência TCP/IP nas camadas inferiores e suporta todos os protocolos padrão físicos e de enlace de dados” (CISCO, 2000).

“As camadas mais afetadas pelo conjunto TCP/IP são a camada 4 (aplicação), a camada 3 (transporte) e a camada 2 (rede). Outros tipos de protocolos, com várias finalidades/funções, todas relativas à transferência de informações, estão incluídos nessas camadas” (CISCO, 2000).

[![low_image4]({{ site.baseurl }}/assets/2012/03/low_image4.jpg)]({{ site.baseurl }}/assets/2012/03/low_image4.jpg)

Figura 4: Modelo TCP/IP

O modelo TCP/IP é divido em camadas de forma a estar em conformidade com o modelo OSI. O Modelo em camadas é um modelo que efetua a separação teórico/prática da função e concorrência dos diversos protocolos.

Basicamente, protocolos contidos em mesma camada são concorrentes, ou seja, não podem aparecer concomitantemente no mesmo pacote de comunicação. Já os protocolos de camadas distintas são complementares, devendo aparecer no mesmo pacote de comunicação. De forma simplificada e omitindo alguns campos para uma melhor compreensão, a figura 5 demonstra os campos de um pacote TCP/IP separado por camadas, bem como a ordem de empacotamento na pilha TCP/IP.

[![low_image5]({{ site.baseurl }}/assets/2012/03/low_image5.jpg)]({{ site.baseurl }}/assets/2012/03/low_image5.jpg)

Figura 5: Sequenciamento de empacotamento TCP/IP

Para um melhor entendimento, a tabela abaixo demonstra alguns exemplos de protocolos em cada uma das camadas.

| **Camada** | **Protocolo** |
| --- | --- |
| Aplicação | DNS, POP3, SMTP, SNMP, HTTP, HTTPS, FTP, TELNET e MSN |
| Transporte | TCP e UDP |
| Rede | IP, ICMP e ARP |
| Física | MAC Address, Ethernet e Frame Relay |

Tabela 1: Exemplos de protocolos por camada TCP/IP

## 1.4. Firewall

Segundo CHESWICK e BELLOVIN apud NAKAMURA e GEUS (2003, p. 206), *firewall* é um ponto entre duas ou mais redes no qual circula todo o tráfego. A partir desse único ponto, é possível controlar e autenticar o tráfego. Já CHAPMAN apud NAKAMURA e GEUS (2003, p. 206) define *firewall* como sendo um componente ou conjunto de componentes que restringe o acesso entre uma rede protegida e a internet ou entre outros conjuntos de redes.

Partindo dessas duas definições, observa-se que o *firewall* é o principal equipamento de ligação e controle entre duas ou mais redes, por onde passa todo o tráfego delas.

Um sistema de *firewall* é composto por vários componentes sendo que cada qual desempenha uma funcionalidade, conforme listado e demonstrado por NAKAMURA e GEUS (2003, p. 208). As quatro primeiras funcionalidades seriam os filtros, proxies, bastion hosts e zonas desmilitarizadas. Porém, com a evolução das necessidades de segurança, foram inseridas ainda neste contexto o Network Address Translation  - NAT, a Rede privada Virtual  - VPN e a autenticação/certificação.

Para se manter de acordo com o objetivo deste estudo, somente os itens filtros e proxies serão detalhados.

### 1.4.1 Filtros

Os filtros são responsáveis por efetuar o controle de pacotes que entram e saem do firewall, na maioria das vezes efetuando o roteamento dos mesmos. O filtro geralmente efetua a análise atuando na camada de rede e de transporte do modelo TCP/IP comparando os dados do cabeçalho do pacote, tais como endereço de origem, endereço de destino, porta de origem, porta de destino, flags e protocolo, com um conjunto de regras estáticas. Segundo NAKAMURA e GEUS (2003, p. 215), esse tipo de *firewall* é conhecido como *static packet filtering*.

Porém, esse tipo de filtragem é vulnerável a diversos tipos de ataques e não se torna compatível com alguns protocolos de camada de aplicação como FTP, RPC e H.323, pois esses utilizam dois ou mais canais de comunicação ou portas dinâmicas (NAKAMURA e GEUS, 2003, p. 215).

Visando solucionar esses e outros problemas e prover uma filtragem mais efetiva e dinâmica, aumentando desta forma a segurança, a Check Point criou o conceito *Stateful Inspection*[[3]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftn3).

Stateful inspection (também conhecido como *dynamic packet filtering*) toma as decisões de filtragem tendo como referência os seguintes elementos:

- As informações dos cabeçalhos dos pacotes, igual o *static packet filtering*;
- Informações recuperadas, armazenadas e manipuladas de todas as camadas do modelo TCP/IP da comunicação corrente ou de outras comunicações. Como por exemplo, o comando de porta de saída de uma sessão FTP;
- Informações provenientes de outros aplicativos, como por exemplo, um usuário autenticado tendo acesso a serviços autorizados;

### 1.4.2. Caching

Antes de falar em proxies é importante se falar em *caching*, pois muitos autores erroneamente definem Proxy como sendo igual à *cache* que, no entanto, são serviços distintos.

Segundo WESSELS (2001, p. 1), o termo *cache* é um termo francês que significa, literalmente, armazenar. Ao se tratar de tecnologia da informação, *caching* se refere ao armazenamento de informações recentemente recuperadas para futura referência e utilização. As informações podem ou não serem utilizadas novamente, fazendo com que o *cache* seja benéfico somente quando o custo computacional de armazenar a informação for inferior ao custo de recuperar ou calcular as informações novamente.

Atualmente, o *caching* é utilizado em várias áreas dentro da computação, como em processadores, sistemas operacionais e outros. Já os serviços para a internet que atualmente mais se utilizam de *cache* são o HTTP e DNS.

### 1.4.3. Proxies

*Proxies* são aplicativos que realizam filtragens mais apuradas em camada de aplicação. Por trabalhar em camada de aplicação, é exigido um código (aplicativo) para cada serviço a ser filtrado.

Atualmente, há basicamente dois tipos de *proxies*, o ativo e o transparente. A principal distinção entre eles é que o ativo necessita de uma personalização dos aplicativos clientes para que se efetue a solicitação do serviço desejado ao p*roxy* e o transparente não precisa da personalização, pois o cliente efetua a solicitação de serviço diretamente ao servidor final e é o firewall que redireciona a solicitação do cliente para o *proxy*. Em ambos, porém, é o servidor de *proxy* que efetua a requisição ao servidor final e retorna o resultado ao cliente.

Alguns serviços de *proxy* existentes no mercado implementam a funcionalidade de *caching* como é o exemplo do *Squid* e o *Microsoft Isa Server*.

# 2. Estudo de caso: Aker Firewall x Ferramentas OpenSource (Linux)

## 2.1. Por que esses produtos?

### 2.1.1. Linux

A escolha do Linux para este estudo se deve ao fato desse sistema se constituir em um dos sistemas operacionais mais utilizados para servidores em geral. A distribuição do Linux escolhida para este estudo foi a da Fedora em sua versão 8. A escolha dessa distribuição e versão se baseia na familiaridade do pesquisador.

### 2.1.2. Aker Firewall

A escolha desse produto foi feita devido ao fato de ser um produto 100% nacional, com qualidade e robustez que o coloca na mesma categoria que os melhores produtos deste ramo no mercado, como Firewall 1 da Checkpoint.

A versão escolhida para este estudo foi a 6.1, por ser a versão comercializada no período deste estudo.

## 2.2. Escopo deste estudo

Este estudo limitar-se-á em comparar as metodologias de implementação de algumas funcionalidades do Aker Firewall com produtos que implementam as mesmas funcionalidades no Linux, tendo como premissa a disponibilidade de somente um hardware para a implementação de cada produto, sem a utilização de máquinas virtuais para aproveitamento do mesmo hardware.

Este estudo não tem a pretensão de exaurir todos os recursos dos dois produtos. Neste, será demonstrada a configuração passo-a-passo para implementação de cada funcionalidade nos produtos, demonstrando telas e arquivos de configuração quando necessários.

As funcionalidades comparadas neste estudo são:

1. Regras de filtragem na camada de transporte;
2. Implementação de QoS;
3. Criação de filtros personalizados em camada de aplicação.

## 2.3. Ambiente

A figura 6 apresenta o detalhamento do ambiente montado para as comparações técnicas.

[![low_image6]({{ site.baseurl }}/assets/2012/03/low_image6.jpg)]({{ site.baseurl }}/assets/2012/03/low_image6.jpg)

Figura 6: Ambiente técnico de implementação

## 2.4. Comparação de funcionalidades

### 2.4.1. Regras de filtragem na camada de transporte

Para esta comparação, serão criadas 3 regras em cada um dos firewalls:

1. Liberação da rede interna para acessar HTTP e HTTPS tendo como destino qualquer faixa de IP;
2. Liberação da rede interna para acessar DNS e MSN tendo como destino qualquer faixa de IP;
3. Bloqueia o restante dos pacotes.

| **Serviço** | **Porta** | **Protocolo** |
| --- | --- | --- |
| HTTP | 80 | TCP |
| HTTPS | 443 | TCP |
| DNS | 53 | UDP |
| MSN | 1863 | TCP |

Tabela 2: Descrição de serviços x porta e protocolo

**Aker Firewall**

O Aker é um produto orientado a objetos, por isso para poder criar qualquer regra, se faz necessário criar os objetos que fazem a representação do mundo real para o produto, os quais são chamados de entidade. A figura 7 mostra quais os tipos de entidades aceitas no produto.

[![Lista de tipos de entidade]({{ site.baseurl }}/assets/2012/03/low_image7.jpg)]({{ site.baseurl }}/assets/2012/03/low_image7.jpg)

Figura 7: Lista de tipos de entidade

Para a criação das regras solicitadas, será necessário criar 6 etidades que serão demonstradas na figura 8.

1) Rede interna,

2) internet,

3) HTTP,

4) HTTPS,

5) DNS,

6) MSN Messenger.

[![Entidades criadas para as regras desta comparação]({{ site.baseurl }}/assets/2012/03/low_image8.jpg)]({{ site.baseurl }}/assets/2012/03/low_image8.jpg)

Figura 8: Entidades criadas para as regras desta comparação

Após a criação das entidades, basta criar as regras, conforme demonstrado na figura 9. Observa-se que o item 3 desta comparação, “bloqueio do restante dos pacotes”, não foi criado. Isso se deve ao fato de que, por padrão, o firewall Aker descarta todos os pacotes, considerando apenas as regras criadas. Observa-se também que não há a necessidade de criar regras de retorno dos pacotes, pois o Aker é *stateful inspection*.

[![Regras de filtragem aplicadas no Aker Firewall]({{ site.baseurl }}/assets/2012/03/low_image9.jpg)]({{ site.baseurl }}/assets/2012/03/low_image9.jpg)

Figura 9: Regras de filtragem aplicadas no Aker Firewall

**Linux**

Para a criação das regras, foi utilizado o aplicativo IPTABLES que vem habilitado por padrão na distribuição escolhida.

Para facilitar a aplicação das regras, serão criadas todas em um arquivo Shell. Dessa forma, a primeira linha do arquivo em questão será “#!/bin/sh”. Logo após esta linha, serão colocados os comandos IPTABLES.

O primeiro comando iptables a ser aplicado efetua a limpeza de todas as regras a fim de evitar que regras antigas ou aplicadas por outros scripts possam influenciar neste equipamento. O comando de limpeza é “iptables --flush”.

Após a limpeza de todas as regras, faz-se necessário definir a regra padrão do IPTABLES, as quais serão definidas com os comandos “iptables -P INPUT DROP”, “iptables -P OUTPUT DROP” e “iptables -P FORWARD DROP”.

As regras de bloqueio estão definidas, sendo necessário começar, então, a criar as regras de liberação. As primeiras regras de liberação que serão criadas são as que permitem os pacotes de conexões pré-estabelecidas. Em seguida, será criada a regra que libera todos os pacotes em *loopback*. As regras são: “iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT”, “iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT”, “iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT” e “iptables -A INPUT -i lo -j ACCEPT”.

Antes de criar as regras específicas solicitadas pela atividade será adicionado um comando para habilitar no kernel do Linux o encaminhamento de pacotes, para que este faça a funcionalidade de roteador “echo 1 > /proc/sys/net/ipv4/ip_forward”.

A partir desse ponto, podem-se criar as regras de liberação específicas solicitadas pela atividade, conforme demonstrado abaixo:

Liberação do HTTP:

iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p TCP --sport 1024:65535 --dport 80 -j ACCEPT

Liberação do HTTPS:

iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p TCP --sport 1024:65535 --dport 443 -j ACCEPT

Liberação do MSN:

iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p TCP --sport 1024:65535 --dport 1863 -j ACCEPT

Liberação do DNS:

iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p UDP --sport 1024:65535 --dport 53 -j ACCEPT

Segue abaixo o arquivo Shell agrupando todas as regras demonstradas acima em um único arquivo nomeado fw.sh.

```bash
#!/bin/sh

# Limpa as regras atuais
iptables --flush

# Regra padrão (Bloqueia tudo)
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Libera os retornos de stados e pacotes de saida
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Liberando tudo da Loopback
iptables -A INPUT -i lo -j ACCEPT

# Libera forward e adiciona as rotas
echo 1 > /proc/sys/net/ipv4/ip_forward

# Regra 1 – Libera o acesso HTTP e HTTPS
iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p TCP --sport 1024:65535 --dport 80 -j ACCEPT
iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p TCP --sport 1024:65535 --dport 443 -j ACCEPT

# Regra 2 – Libera o acesso DNS e MSN
iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p TCP --sport 1024:65535 --dport 1863 -j ACCEPT
iptables -A FORWARD -i eth1 -s 172.31.2.0/24 -d 0.0.0.0/0 -o eth0 -p UDP --sport 1024:65535 --dport 53 -j ACCEPT
```

**Aker Firewall x Linux**

Pode-se observar nessa comparação que devido à utilização de uma interface gráfica, a configuração no Aker fica mais intuitiva ao administrador, dando-lhe a clareza das configurações por se aproximar com o desenho de seu ambiente. Dessa forma, o administrador tem um ganho de produtividade com a redução do tempo de implementação e gestão das regras de filtragem.

### 2.4.2. Implementação de QoS

Para esta comparação, deverá ser implementado um QoS de 2 Mbps simétrico, ou seja, de download e upload, para os protocolos HTTP e HTTPS.

**Aker Firewall**

Para a implementação do QoS no Aker, será criada uma entidade do tipo “Canal”, conforme a figura 10. Após a criação da entidade, serão aproveitadas as mesmas regras de filtragem criadas na comparação anterior e será inserido o canal na regra necessária, conforme mostrado na figura 11.

[![Entidade do tipo canal]({{ site.baseurl }}/assets/2012/03/low_image10.jpg)]({{ site.baseurl }}/assets/2012/03/low_image10.jpg)

Figura 10: Entidade do tipo canal

[![Regras de filtragem aplicadas no Aker Firewall com QoS]({{ site.baseurl }}/assets/2012/03/low_image11.jpg)]({{ site.baseurl }}/assets/2012/03/low_image11.jpg)

Figura 11: Regras de filtragem aplicadas no Aker Firewall com QoS

**Linux**

Para a criação do QoS foi utilizado o aplicativo tc, que também está instalado por padrão na distribuição escolhida. O tc aplica as políticas de QoS com base nos pacotes de saída da placa física da máquina. Dessa forma, faz-se necessária a criação de duas políticas distintas, uma para upload de pacotes e outra para download.

Para uma melhor compreensão dos comandos, a figura 12, criada por BALLIACHE, ilustra a sequência de ligação entre os elementos do tc.

[![Elementos do TC]({{ site.baseurl }}/assets/2012/03/low_image12.jpg)]({{ site.baseurl }}/assets/2012/03/low_image12.jpg)

Figura 12: Elementos do TC

Os elementos definidos pelo tc são os seguintes:

1. Queuing Disciplines = qdisc

Algoritmos que controlam o enfileiramento e envio de pacotes.

1. Classes

Representam “entidades de classificação de pacotes”.

1. Filters

Utilizados para policiar e classificar os pacotes e atribuí-los as classes.

1. Policers

Utilizados para evitar que o tráfego associado a cada filtro ultrapasse limites pré-definidos.

**Política de upload:**

Exclusão da qdisc principal e todos os objetos vinculados:

tc qdisc del dev eth0 root

Criação da qdisc principal:

tc qdisc add dev eth0 handle 1:0 root htb

Criação da classe:

tc class add dev eth0 parent 1:0 classid 1:1 htb rate 128kbps

Criação da qdisc da classe:

tc qdisc add dev eth0 parent 1:1 handle 10:0 pfifo limit 10

Aplicação dos filtros:

tc filter add dev eth0 parent 1:0 protocol ip prio 2 u32 match ip dport 80 0xfff flowid 1:1

tc filter add dev eth0 parent 1:0 protocol ip prio 2 u32 match ip dport 443 0xfff flowid 1:1

**Política de download:**

Exclusão da qdisc principal e todos os objetos vinculados:

tc qdisc del dev eth1 root

Criação da qdisc principal:

tc qdisc add dev eth1 handle 2:0 root htb

Criação da classe:

tc class add dev eth1 parent 2:0 classid 2:1 htb rate 2048kbps

Criação da qdisc da classe:

tc qdisc add dev eth1 parent 2:1 handle 30:0 pfifo limit 10

Aplicação dos filtros:

tc filter add dev eth1 parent 2:0 protocol ip u32 match ip dst 0.0.0.0/0 match ip sport 80 0xfff flowid 2:1

tc filter add dev eth1 parent 2:0 protocol ip u32 match ip dst 0.0.0.0/0 match ip sport 443 0xfff flowid 2:1

Segue abaixo o arquivo Shell agrupando todas as regras demonstradas acima. Este foi nomeado como qos.sh

```bash
#!/bin/bash

# POLITICA DE UPLOAD (eth0)
tc qdisc del dev eth0 root
tc qdisc add dev eth0 handle 1:0 root htb
tc class add dev eth0 parent 1:0 classid 1:1 htb rate 128kbps
tc qdisc add dev eth0 parent 1:1 handle 10:0 pfifo limit 10
tc filter add dev eth0 parent 1:0 protocol ip prio 2 u32 match ip dport 80 0xfff flowid 1:1
tc filter add dev eth0 parent 1:0 protocol ip prio 2 u32 match ip dport 443 0xfff flowid 1:1

# POLITICA DE DOWNLOAD (eth1)
tc qdisc del dev eth1 root
tc qdisc add dev eth1 handle 2:0 root htb
tc class add dev eth1 parent 2:0 classid 2:1 htb rate 2048kbps
tc qdisc add dev eth1 parent 2:1 handle 30:0 pfifo limit 10
tc filter add dev eth1 parent 2:0 protocol ip u32 match ip dst 0.0.0.0/0 match ip sport 80 0xfff flowid 2:1
tc filter add dev eth1 parent 2:0 protocol ip u32 match ip dst 0.0.0.0/0 match ip sport 443 0xfff flowid 2:1
```

**Aker Firewall x Linux**

Tendo como foco a clareza no entendimento da aplicação das funcionalidades, o tc se mostrou pouco favorável, demandando um tempo maior do administrador no entendimento dos comandos, aplicação e gestão dessa regra de QoS. Em contrapartida, o Aker aproveitou um ambiente já montado e de fácil compreensão ao administrador para implementar a regra de QoS.

### 2.4.3. Criação de filtros personalizados em camada de aplicação.

O objetivo deste teste é comparar a capacidade dos dois produtos em realizar filtro específico (criado pelo administrador) em camada de aplicação, para liberação ou bloqueio de uma conexão.

**Aker firewall**

Para a implementação de um filtro em camada de aplicação, é necessário criar um filtro com um texto personalizado que se deseja buscar nos pacotes, conforme demonstrado na figura 13, e posteriormente aplicá-lo em uma regra de filtragem de aplicações, conforme demonstrado na figura 14.

[![Criação do filtro de aplicações]({{ site.baseurl }}/assets/2012/03/low_image13.jpg)]({{ site.baseurl }}/assets/2012/03/low_image13.jpg)

Figura 13: Criação do filtro de aplicações

[![Criação da regra de filtragem de aplicações]({{ site.baseurl }}/assets/2012/03/low_image14.jpg)]({{ site.baseurl }}/assets/2012/03/low_image14.jpg)

Figura 14: Criação da regra de filtragem de aplicações

**Linux**

Para a criação deste tipo de filtragem no Linux, é necessário recompilar o Kernel e o iptables com o módulo Layer7[[4]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftn4).

Para a compilação do kernel e iptables foi utilizado o artigo de ROBERTO (2007), conforme segue abaixo:

Passo 1 – Download dos pacotes[[5]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftn5):

linux-2.6.23.tar.bz2

iptables-1.3.8.tar.bz2

l7-protocols-2007-11-22.tar.gz

netfilter-layer7-v2.14.tar.gz

Passo 2 – remoção do Iptables

# yum remove iptables

Passo 3 – Descompactar os pacotes em /usr/src

# cd /usr/src

# tar xjvf linux-2.6.23.tar.bz2

# tar xjvf iptables-1.3.8.tar.bz2

# tar xzvf netfilter-layer7-v2.14.tar.gz

# tar xzvf l7-protocols-2007-11-22.tar.gz

# mkdir /etc/l7-protocols

# cp -a /usr/src/l7-protocols-2007-11-22/protocols/ /etc/l7-protocols/

Passo 4 – Criar links simbólicos

# ln -s /usr/src/linux-2.6.23 /usr/src/Linux

# ln -s /usr/src/iptables-1.3.8 /usr/src/iptables

Passo 5 – Aplicar os patchs no kernel e no iptables e configurar o layer7

# cd /usr/src/linux

# patch -p1 < /usr/src/netfilter-layer7-v2.14/kernel-2.6.22-layer7-2.14.patch

# cd /usr/src/iptables

# patch -p1 < /usr/src/netfilter-layer7-v2.14/iptables-for-kernel-2.6.20forward-layer7-2.14.patch

# cd /usr/src/linux

# make menuconfig

Neste ponto, é necessário selecionar o Layer7 para posterior compilação junto com o kernel. Então, navegue com o teclado até a opção:

Networking

Networking Options

Network packet filtering framework (Netfilter)

Core Netfilter Configuration

Ao encontrar a opção < > “layer7" match support, marque-a com um M, e a que vem logo abaixo dela, com um asterisco, ficando assim:

<M> “layer7" match support

[*] Layer 7 debugging output

Salve e saia do menuconfig.

Passo 5 – Compilar o kernel

# make dep

# make clean

# make bzImage

# make modules

# make modules_install

# make install

Após a compilação, reinicie a máquina e selecione o kernel novo compilado, pois o kernel antigo e o padrão de boot.

Passo 6 – Definir permissões e compilar o iptables.

# chmod 755 extensions/.layer7-test

# make KERNELDIR=/usr/src/linux

# make KERNELDIR=/usr/src/linux install

Passo 7 – Se necessário, habilitar o módulo no kernel.

# modprobe ipt_layer7

Agora basta efetuar a criação do Pattern de consulta e aplicar a regra no iptables.

Conteúdo do arquivo “/etc/l7-protocols/protocols/terra.pat”

terra

terra.com*

Regra do iptables

iptables -I FORWARD -m layer7 --l7proto terra -s any/0 -p TCP --sport 1024:65535 --dport 80  -j DROP

**Aker Firewall x Linux**

O kernel do Linux e o iptables não implementam em modo nativo a funcionalidade de filtragem em camada de aplicação.Dessa forma, há a necessidade de utilizar um módulo de terceiros anexo ao iptables e ao kernel do Linux para habilitar essa funcionalidade, além de haver a necessidade de efetuar a recompilação do kernel. No entanto, como afirma KROAH-HARTMAN (2007, p. ix), esse pocesso de recompilação é um processo incompreensível para a maioria das pessoas.

O Aker implementa de forma nativa a filtragem de aplicação de forma intuitiva e de rápida aplicação, bastando apenas criar o filtro e a regra de filtragem de aplicação desejada. Indo além dessa configuração trivial, é possível com o Aker configurar nessa mesma regra de filtragem de aplicação que essa conexão seja policiada com QoS.

# 3. Conclusão

Observou-se neste estudo que a informação é um bem valioso para a empresa, assim como seus ativos físicos, merecendo uma atenção no tocante a segurança dessa informação. Aprofundando-se no ambiente da segurança de informação, este estudo demonstra que a segurança da informação está baseada em 3 pilares bases: confidencialidade, integridade e disponibilidade, sendo que quando se retira um desses pilares, acontece o que se conceitua como incidente de segurança da informação.

Quando se fala de incidente de segurança, logo se imagina um ataque hacker. Porém, há outros incidentes que também são prejudiciais ao ambiente corporativo, como o acesso indevido de colaboradores a recursos computacionais, sendo eles internos ou externos, e de colaboradores tentando burlar o sistema de proteção e filtragem HTTP, MSN, e-mail e outros. Essas e outras atividades que caracterizam uma tentativa de ataque podem evoluir para um incidente e precisam ser tratadas, através de uma política de segurança que utilizará ferramentas para evitar um incidente de segurança.

Nesse escopo, há algumas ferramentas importantes para controlar esses acessos, como os *firewalls* e *proxies*. Hoje, há no mercado, uma grande variedade de softwares de firewall e *proxy*, sendo que alguns deles se integram em um único produto e outros trabalham de forma independente. Neste cenário, um dos sistemas mais utilizados para esses fins é o Linux, por ser, aparentemente, um recurso mais acessível, já que não há o custo de licenças. Porém, recentemente, um estudo dirigido pela Microsoft mostrou que o custo de licenciamento corresponde a 5% do custo efetivo total de um servidor (FOLHA, 2002) e que há custos, muitas vezes não contabilizados, como o valor da hora de trabalho do profissional que administra esses equipamentos na empresa.

A administração de um sistema de proteção de segurança de informação como um *firewall* e *proxy* baseado em Linux, demanda do profissional não só um conhecimento na tecnologia, mas também um profundo conhecimento do sistema operacional Linux. Outra desvantagem desse tipo de sistema, é a falta de padronização, pois cada distribuição Linux tem uma metodologia de implementação e cada profissional tem sua própria metodologia de implementação.

É importante ressaltar que os sistemas Linux são tecnicamente ótimos produtos e utilizados em larga escala, porém, geralmente, não há uma preocupação em se ter uma boa produtividade e clareza das configurações no momento de sua gestão.

Objetivando ilustrar o ganho de clareza, ou seja, o entendimento da metodologia de implementação e funcionalidade dos recursos de um firewall e Proxy, bem como o ganho de produtividade em suas 5 abordagens definidas por PARKINSON, este estudo efetuou a comparação da metodologia de implementação de 3 atividades distintas entre o Firewall Aker e sistemas baseado em Linux.

Porém, sugere-se uma continuidade deste estudo com algumas outras comparações, todas elas possíveis de serem implementadas de forma simples e objetiva no firewall Aker:

1. Regras de liberação e bloqueios de site com autenticação aplicando perfil de navegação distinto para grupos de usuários;
2. Aplicação de quota de navegação por tempo e/ou tráfego HTTP e MSN;
3. Aplicação de QoS por categorias/lista de sites;
4. Regras de firewall e Proxy com habilitação automática tendo como base dias e horários da semana;
5. Bloqueios por tipo de navegador;
6. Reescrita de URL;
7. Aplicação de Proxy MSN com filtragem por domínios, e-mails, aplicativos liberados e transferência de arquivos;
8. Implementação em modo cluster com replicação automática das configurações entre os nós do cluster.

Em termos de clareza no entendimento da função de uma determinada regra, o firewall Aker tem uma vantagem considerável, pois sua console de gerenciamento é uma console gráfica podendo trabalhar em dois idiomas (português e inglês), não necessitando o conhecimento profundo em comandos e estrutura do sistema operacional base.

Nas três comparações efetuadas, pode-se observar que em cada uma delas foi utilizado um aplicativo diferente. Dessa forma, configurações distintas puderam ser aplicadas de forma distinta, dependendo do administrador desse sistema. Na terceira comparação, houve a necessidade de efetuar a compilação do Kernel do Linux a qual nem sempre é um processo intuitivo. como afirma KROAH-HARTMAN (2007, p. ix):

“A compilação do Kernel Linux parece simples para quem está familiarizado, porém é incompreensível para a maioria das pessoas, pois não há um local onde toda a informação necessária para este processo é encontrada de forma clara e objetiva”.

Neste estudo, pode-se, então, implementar todas as funcionalidades propostas nos dois produtos estudados, porém no firewall Aker houve um ganho de produtividade e clareza da aplicabilidade das regras e filtros propostos.

# Referencias Bibliográficas

AKER, Security Solutions, **Manual de treinamento: Aker Firewall 6.1**. Disponível em: < http://www1.aker.com.br/005/00502001.asp?ttCD_CHAVE=22239>. Acesso em: 13 mar. 2010.

ABNT NBR ISO/IEC 27002:2005, **Código de prática para a gestão da segurança da informação**

BALLIACHE, Leonardo, **Linux Queuing Disciplines**. Disponível em: <http://www.opalsoft.net/qos/DS.htm>. Acesso em: 13 mar. 2010

CAMPOS, André L. N., **Sistema de Segurança da Informação: Controlando os Riscos**. ed. Florianópolis: Campus, 2006.

CARVALHO, Gustavo, **Qualidade de Serviços para Gateways Linux (QoS)**. Disponível em: <http://www.vivaolinux.com.br/artigo/Qualidade-de-Servicos-para-Gateways-Linux-(QoS)>. Acesso em: 13 mar. 2010

CHIAVENATO, I., **Gestão de Pessoas: o novo papel dos recursos humanos nas organizações**. ed. Rio de Janeiro: Campus, 1999.

CISCO, **Networking Academy – Semestre 2 do CCNA v.2.1**. 2000.

DAVENPORT, T. H. **Ecologia da informação: por que só a tecnologia não basta para o sucesso na era da informação**. ed. São Paulo : Futura, 1998

DUSSIN, Marco e FERRO, Nicola, **The Role of the DIKW Hierarchy in the Design of a Digital Library System for the Scientific Data of Large-Scale Evaluation Campaigns.** Disponível em: <http://www.ieee-tcdl.org/Bulletin/v5n1/Dussin/dussin2.html>. Acesso em: 13 mar. 2010.

FOLHA, **Microsoft diz que o Windows é mais barato do que o Linux**. Disponível em: < http://www1.folha.uol.com.br/folha/informatica/ult124u11484.shtml>. Acesso em: 13 mar. 2010.

ISO/IEC 13335-1:2004, **Information technology — Security techniques — Management of information and communications technology security — Part 1: Concepts and models for information and communications technology security management**

JAKOBSON, Roman, **Linguistica e Comunicação**. ed. São Paulo: Cultrix, 2001.

KROAH-HARTMAN, Greg, **Linux Kernel in a Nutshell**, ed. Estados Unidos: O’Reilly, 2007.

MACEDO, Mariano de Matos, **Gestão da produtividade nas empresas**, ed. Curitiba: revista FAE Bussines n. 3 set, 2002.

MICHAELIS, Dicionário, **Moderno Dicionário da Língua Portuguesa**. Disponível em: <http://michaelis.uol.com.br/ >. Acesso em: 11 mar. 2010.

MOTA, J. E., **Firewall com IPTABLES**: Disponível em:  <http://www.eriberto.pro.br/iptables/3.html>. Acesso em: 13 mar. 2010.

NAKAMURA, Emilio Tissato e GEUS, Paulo Licio, **Segurança de redes em ambientes cooperativos**, ed. São Paulo: Futura, 2003.

PARKINSON, John, **The Pursuit of Productivity**, CIOInsight 01 abril, 2004.

ROBERTO, Gustavo, **Implementando Iptables Layer 7 no Fedora Core 7 e 8**. Disponível em: < http://www.gustavoroberto.blog.br/2007/12/09/implementando-iptables-layer-7-no-fedora-core-7-e-8/>. Acesso em: 13 mar. 2010.

SÊMOLA, Marcos, **Gestão da Segurança da Informação: uma visão executiva**. ed. Rio de Janeiro: Campus, 2003.

SETZER, Valdemar W., **Dado, Informação, Conhecimento e Competência**. Disponível em: < http://www.ime.usp.br/~vwsetzer/dado-info.html >. Acesso em: 13 mar. 2010.

WESSELS, Duane, Web Caching, ed. Estados Unidos: O’Reilly, 2001.

---

[[1]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftnref1) A informação é elemento essencial para todos os processos de negócio da organização, sendo, portanto, um bem ou ativo de grande valor. CAMPOS (2006, p. 9)

[[2]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftnref2) Relação adaptada pelo autor, visando focar no objeto deste estudo, tendo como fonte CAMPOS (2006, p. 11 e 12)

[[3]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftnref3) Este termo é patenteado pela Check Point Software Technologies Ltda.

[[4]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftnref4) http://l7-filter.sourceforge.net

[[5]](file:///C:/Users/g0024485/Desktop/Publicar/TCC_Final.docx#_ftnref5) Segue o link para download dos pacotes, Acesso em: 13 mar 2010:

http://www.kernel.org/pub/linux/kernel/v2.6/linux-2.6.23.tar.bz2

http://www.netfilter.org/projects/iptables/files/iptables-1.3.8.tar.bz2

http://ufpr.dl.sourceforge.net/sourceforge/l7-filter/l7-protocols-2007-11-22.tar.gz

http://ufpr.dl.sourceforge.net/project/l7-filter/l7-filter%20kernel%20version/2.14/netfilter-layer7-v2.14.tar.gz
