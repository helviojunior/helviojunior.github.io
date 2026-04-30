---
layout: post
title: Introdução a Criptografia (Criptografia, hash, base64 encoding e certificação
  digital)
date: 2012-03-07 03:37:40.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Segurança da Informação
tags:
- autoridade certificadora
- ca
- certificate authority
- openssl
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/introducao-criptografia/"
---

Este artigo objetiva demonstrar os conceitos iniciais de criptográfica com chave assimétrica e certificação digital.

<!--more-->

## 1.     O que é criptografia?

A criptografia é o processo pelo qual se transforma dados legíveis em algo sem sentido (ilegível), porém sendo capaz de recuperar os dados originais a partir dessas dados sem sentido. A criptografia é uma das ferramentas mais importantes para a proteção dos dados, sejam eles em trânsito ou armazenado. Mas vale a pena ressaltar que a criptografia não é à prova de falhas e toda criptografia pode ser quebrada e, sobretudo, se for implementada incorretamente, ela não agrega nenhuma segurança real.

### Porque a chave é necessária?

Toda criptografia computadorizada opera com chaves, pois manter o algoritmo criptográfico em segredo é algo inviável, sendo assim para proteger os dados basta utilizar um algoritmo de criptografia forte e proteger a chave utilizada. Isso significa também que pode ser utilizado chaves diferentes para proteger diferentes informações, sendo assim, se alguém quebrar uma das chaves, as outras informações ainda estarão seguras.

## 2.     Criptografia de chave simétrica

Nesta abordagem, um algoritmo utiliza uma chave para converter as informações naquilo que se parece com bits aleatórios. Assim, o mesmo algoritmo utiliza a mesma chave para recuperar os dados originais.

Esta metodologia tem desempenho bem melhores em se comparado com a criptografia de chave assimétrica, porém como para recuperar os dados cifrados, você também necessita das mesmas chaves que foram utilizadas para cifrar os dados é necessário um bom gerenciamento dessas chaves. Em se tratando de comunicação de via rede este problema da gestão da chave é mais evidente, pois para que dois ativos possam se comunicar os dois necessita conhecer a mesma chave, desta forma tem-se um problema: ou os dois ativos detêm a chave antes do início da comunicação ou a chave necessita ser transmitida via rede sem criptografia.

Segue abaixo a imagem ilustrando a utilização do mesmo algoritmo e chave para cifrar a decifrar a mensagem.

[![Chave-Simetrica]({{ site.baseurl }}/assets/2012/03/image1.jpeg)]({{ site.baseurl }}/assets/2012/03/image1.jpeg)

## 3.     Criptografia de chave assimétrica

Este esquema utiliza duas chaves diferentes. Mesmo estando relacionadas entre si – elas são parceiras – elas são significativamente diferentes. O relacionamento é matemático; o que uma chave encripta a outra chave decripta. Na criptografia simétrica, a mesma chave é utilizada para encriptar e decriptar (daí a palavra “simétrica” – partes correspondentes); se utilizar outra chave qualquer para decriptar, o resultado será algo sem sentido. Mas com a criptografia assimétrica (conforme imagem abaixo), a chave que é utilizada para encriptar os dados não é utilizada para decriptá-los; apenas a parte correspondente pode (daí palavra “assimétrica” – partes não-correspondentes).

Em outras palavras, a chave privada deve permanecer em segredo, enquanto a chave pública pode ser publicada sem qualquer perigo. Neste exemplo é utilizada a **chave publica** para **criptografar** os dados, porém somente a **chave privada** pode **decriptografar**.

[![chave-assimetrica]({{ site.baseurl }}/assets/2012/03/image2.jpeg)]({{ site.baseurl }}/assets/2012/03/image2.jpeg)

Quando utilizado o algoritmo RSA, qualquer coisa que tenha sido encriptado com a chave pública pode ser decifrado apenas com a chave privada. Bem como qualquer coisa que tenha sido enncriptado com a chave privada pode ser decrifrado apenas com a chave pública. Isto demonstra que o RSA funciona tanto do privado ao público, como do público ao privado.

## 4.     Assinatura digital

Quando se utiliza a chave privada para criptografar os dados, apenas a chave pública pode ser utilizada para decriptografar os dados. Este processo não fornece segurança uma vez que que a chave pública, conceitualmente pode ser conhecida por todos, então para que serve este processo? Para assinatura digital. Pois como somente o proprietário da chave privada pode gerar a informação criptografada, ao descriptografar com a chave pública tem-se a garantia de que o dado criptografado veio de quem diz ser.

Desta forma as assinaturas digitais detém duas suposições fundamentais: primeiro, que a chave privada seja segura e que apenas o proprietário da chave tenha acesso a ela e, segundo, que a única maneira de produzir uma assinatura digital seja utilizando a chave privada.

A Assinatura digital resolve duas questões relacionadas à criptografia: autenticação e não repúdio. A autenticação permite que alguém no mundo eletrônico confirme dados e identidade, e o não repúdio impede que pessoas retifiquem sua palavra eletrônica.

A forma mais comum de assinatura digital conhecida é o certificado digital. Um certificado digital associa um nome a uma chave pública. O certificado digital é produzido de tal maneira que o torna perceptível se um impostor pegou o certificado existente e substituiu a chave pública ou o nome.

## 5. Hash

Hash, ou resumo da mensagem é um algoritmo que recebe qualquer comprimento de entrada (de dados/mensagem) e mescla a entrada para produzir uma saída pseudoaleatória de largura fixa.  Hash detém algumas propriedades:

- **Propriedade 1:** Um mesmo algoritmo de hash sempre condensará (reduzir, resumir) o conteúda da entrada de dados em uma saída de tamanho fixo independentemente do tamanho, e do que, for fornecido como entrada;
- **Propriedade 2:** A saída de um algoritmo de hash é pseudoaleatória por diversas questões e princípios matemáticos;
- **Propriedade 3:** Mesmo que os dados de entrada seja quase idêntico (mudando apenas 1 bit, por exemplo), o a saída será dramaticamente diferente;
- **Propriedade 4:** Não pode reconstruir a mensagem de entrada (mensagem original) a partir de uma saída hash, este princípio é conhecido como função de uma única via;
- **Propriedade 5:** Um bom algoritmo de hash não são tão fáceis de examinar;
- **Propriedade 6:** Não é possível localizar uma mensagem que produza um hash em particular;
- **Propriedade 7:** Um bom algoritmo de hash não pode encontrar duas mensagens que produzam uma mesma saída;

### Hash e Colisões

Até o momento da escrita deste post não existe nenhum algoritmo capaz de satisfazer as propriedades 6 e 7 de forma perfeita,  então quando um algoritmo de hash viola as duas ultimas propriedades, o resultado é uma colisão, o termo técnico para descrever uma situação em que duas mensagens produzem um mesmo hash.

Segue abaixo uma tabela com as informações dos principais hashes utilizados atualmente:

[![]({{ site.baseurl }}/assets/2012/03/Hashes.png)]({{ site.baseurl }}/assets/2012/03/Hashes.png)

### Diferença principal entre Criptografia e Hash

Este é um tema controverso, dependendo da literatura que se adota, sendo assim para este estudo vamos entender de forma geral como sendo:

- **Criptografia:** Reversível;
- **Hash:** Não reversível;

## 6.     Infraestrutura de chave pública e o padrão X.509

Um certificado de chave pública (public-key certificate – PKC) é um conjunto de dados à prova de falsificação que atesta a associação de uma chave pública a um usuário final. Para fornecer essa associação, um conjunto de terceiros confiáveis confirma a identidade do usuário. Os terceiros chamados de autoridades certificadoras (certification authorities – Cas), emitem certificados para o usuário com o nome de usuário, a chave pública e outras informações que o identifiquem. Após serem assinados digitalmente pela CA, esses certificados podem ser transferidos e armazenados.

O formato de certificado mais amplamente aceito é o X.509 Versão 3. Em 1999 foi publicado um perfil para o X.509 na RFC2459.

Todas as versões dos certificados X.509 contêm os seguintes campos:

| **Campo** | **Descrição** |
| --- | --- |
| **Version (Versão)** | Este campo deferência as sucessivas versões do certificado, como Versão 1, Versão 2 e Versão 3. O campo Versão também permite possíveis versões futuras. |
| **Certificate Serial Number (Número serial de certificado)** | Esse campo contém um valor de inteiro único em cada certificado. É gerado pela CA. |
| **Signature Algorithm Identifier (Identificador do algoritmo de assinatura)** | Este campo indica o identificador do algoritmo utilizado para assinar o certificado junto com quaisquer parâmetros associados. |
| **Issue Name (Nome do emissor)** | Esse campo identifica o nome distinto (distinguished name – DN) com o qual a CA cria e assina esse certificado. |
| **Validity (Not before/After) (Validade – Não antes/Não depois)** | Esse campo conte´m dois valores de data/hora – Not Valid Before e Not Valid After – que definem o período que esse certificado pode ser considerado válido a menos que, caso, contrário, seja revogado. |
| **Subject Name (Nome do sujeito)** | Esse campo identifica o DN da entidade final a que o certificado se refere, isto é, o sujeito que mantém a chave privada correspondente. Esse campo deve ter uma entrada, a menos que um nome alternativo seja utilizado nas extensões da Versão 3. |
| **Subject Public Key Information (Informação sobre a chave pública do sujeito)** | Esse campo contém o valor da chave pública so sijeito, bem como o identificador de algoritmo e quaisquer parâmetros associados ao algoritmo pelos quais a chave deve ser utilizada. Esse campo sempre deve ter uma entrada. |

Os certificados versões 2 e 3 podem conter outros campos com:

- Issue Unique Identifier (identificador único de emissor)
- Subject Unique Identifier (Identificador único de sujeito)
- Extensions (Extensões) (Somente versão 3)
  - Authority Key Identifier (Identificador de chave de autoridade)
  - Subject Key Identifier (Identificador de chave de sujeito)
  - Key Usage (Utilização de chave)
  - Extened Key Usage (Utilização de chave estendida)
  - CRL Distribution Point (Ponto de distribuição de CRL)
  - Private Key Usage Period (Período de uso de chave privada)
  - Certificate Policies (Políticas de certificado)
  - Policy Mapping (Mapeamento de políticas)
  - Subject Alternate Name (Nome alternativo so sujeito)
  - Issue Alternate Name (Nome alternativo do emissor)
  - Subject Directory attributes (Atributos do diretório do sujeito)
  - Basic Constraints (Restições básicas)
  - Name Constraints (Restições de nome)
  - Policy Constraints (Restições de diretiva)

Com foco no estudo deste documento as únicas extensões que iremos descrever é a **Basic Constraints (Restições básicas)** e **Certificate Policies (Políticas de certificado).**

- Basic Constraints (Restições básicas)

Essa extensão indica se o sujeito pode agir como uma CA, fornecendo uma maneira para restringir que usuários finais atuem como CAs. Se este campo estiver presente, também poderá ser especificado um comprimento do caminho de certificaçã. O comprimento do caminho de certificação limita os poderes certificadores de uma nova autoridade (por exemplo, se a Verisign poderia permitir que a RSA Inc. atuasse como uma CA, mas ao mesmo tempo, não permitisse que a RSA Inc. criasse novas CAs). A RFC2459 ordena que essa extensão esteja presente e marcada como crítica em todos os certificados de CA.

- Certificate Policies (Políticas de certificado)

Essa extensão identifica as informações sobre as políticas e qualificadores opcionais que a CA associa ao certificado. Se essa extensão for marcada como crítica, o aplicativo de processamento deve seguir pelo menos uma das políticas indicadas ou o certificado não deverá ser utilizado.

### 6.1.           Hierarquia de certificado

À medida que uma população de PKI (public-key infraestructure) começa a aumentar, torna-se difícil para uma CA monitorar de maneira eficaz a identidade de todas as partes que ela certificou. Uma solução é utilizar uma hierarquia de certificados, onde uma CA delega sua autoridade para uma ou mais autoridades subsidiarias. Essas autoridades, por sua vez, designam seus próprios subsidiários. A figura abaixo ilustra o conceito de hierarquia de certificados.

[![Hierarquia de certificação]({{ site.baseurl }}/assets/2012/03/image3.jpeg)]({{ site.baseurl }}/assets/2012/03/image3.jpeg)

Um recurso poderoso das hierarquias de certificado é que nem todas as partes devem confiar automaticamente em todas as autoridades certificadoras. De fato, a única autoridade cuja confiança deve ser estabelecida por todos é a CA superior. Por causa da sua posição na hierarquia, essa autoridade é geralmente conhecida como autoridade raiz. Os exemplos atuais de CAs de raiz pública incluem Verisign, Thawte e a raiz de CA do U.S Postal Service.

## 7.     Padrão PKCS#12

O formato PKCS#12 foi criado pela “RSA Laboratories” para armazenamento do certificado X.509 acompanhado da chave privada. Esse arquivo geralmente tem a extensão “pfx” e “p12”.

## 8.     Bas64 encoding

**Base64 NÃO é criptografia é um algoritmo de codificação**

Base64 é um método para codificação de dados para transferência na Internet (codificação MIME para transferência de conteúdo). É utilizado frequentemente para transmitir dados binários por meios de transmissão que lidam apenas com texto, como por exemplo para enviar arquivos anexos por e-mail. É constituído por 64 caracteres ([A-Z],[a-z],[0-9], "/" e "+") que deram origem ao seu nome.

Exemplo:

- Texto original: Treinamento Desenvolvimento Seguro
- Texto convertido para Base64: VHJlaW5hbWVudG8gRGVzZW52b2x2aW1lbnRvIFNlZ3Vybw==

Busca parcial

- Texto anterior completo convertido para Base64: VHJlaW5hbWVudG8gRGVzZW52b2x2aW1lbnRvIFNlZ3Vybw==
- Texto original: Desenvolvimento
- Texto convertido para Base64: RGVzZW52b2x2aW1lbnRv

## 9.     Referencias bibliográficas

BURNETT, Steve, **Criptografia e segurança: o guia oficial RSA,** tradução de Edson Fumankiewcz. Ed. Rio de Janeiro: Elsevier, 2002.

https://tools.ietf.org/html/rfc4648
